/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package detector

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// SourceValue reads an immutable rule-input value without constructing another
// document tree. Engine adapters can use the OPA payload after native maps have
// been released; direct detector callers use NativeSourceValue.
type SourceValue interface {
	Kind() reflect.Kind
	Field(string) (SourceValue, bool)
	Keys() []string
	Element(int) SourceValue
	Length() int
	Text() string
	Identity() SourceIdentity
}

type SourceIdentity struct {
	Pointer uintptr
	Length  int
}

type NativeSourceValue struct{ Value interface{} }

// WrittenSourceValue marks configuration whose source bookkeeping lives outside
// its fields. Names such as id and _dd_lines therefore remain searchable data.
func WrittenSourceValue(value SourceValue) SourceValue { return writtenSourceValue{value} }

type writtenSourceValue struct{ SourceValue }

func (v writtenSourceValue) Field(key string) (SourceValue, bool) {
	child, ok := v.SourceValue.Field(key)
	if !ok {
		return nil, false
	}
	return writtenSourceValue{child}, true
}
func (v writtenSourceValue) Element(index int) SourceValue {
	return writtenSourceValue{v.SourceValue.Element(index)}
}

func (v NativeSourceValue) Kind() reflect.Kind {
	switch v.Value.(type) {
	case model.Document, map[string]interface{}:
		return reflect.Map
	case []interface{}:
		return reflect.Slice
	default:
		return reflect.Invalid
	}
}
func (v NativeSourceValue) Field(key string) (SourceValue, bool) {
	var fields map[string]interface{}
	switch value := v.Value.(type) {
	case model.Document:
		fields = value
	case map[string]interface{}:
		fields = value
	}
	value, ok := fields[key]
	return NativeSourceValue{Value: value}, ok
}
func (v NativeSourceValue) Keys() []string {
	var fields map[string]interface{}
	switch value := v.Value.(type) {
	case model.Document:
		fields = value
	case map[string]interface{}:
		fields = value
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func (v NativeSourceValue) Element(index int) SourceValue {
	return NativeSourceValue{Value: v.Value.([]interface{})[index]}
}
func (v NativeSourceValue) Length() int { return len(v.Value.([]interface{})) }
func (v NativeSourceValue) Text() string {
	if v.Kind() != reflect.Invalid {
		return ""
	}
	if v.Value == nil {
		return "null"
	}
	return fmt.Sprint(v.Value)
}
func (v NativeSourceValue) Identity() SourceIdentity {
	if v.Kind() == reflect.Map {
		return SourceIdentity{Pointer: reflect.ValueOf(v.Value).Pointer()}
	}
	if v.Kind() == reflect.Slice {
		return SourceIdentity{Pointer: reflect.ValueOf(v.Value).Pointer(), Length: v.Length()}
	}
	return SourceIdentity{}
}

type sourceSelector struct {
	key       string
	value     *string
	literal   string
	remaining []string
}

func sourceSelectors(searchKey string) []sourceSelector {
	segments, extracted := splitProtectedSearchKey(searchKey, legacySearchKeyPlaceholder, splitTopLevelDots)
	restored := make([]string, len(segments))
	for index, segment := range segments {
		restored[index] = resolvePlaceholders(segment, extracted)
	}
	var selectors []sourceSelector
	for segmentIndex, segment := range segments {
		equal := -1
		depth := 0
		for i := 0; i < len(segment); i++ {
			switch segment[i] {
			case '"', '\'':
				i = skipQuotedSearchKey(segment, i)
			case '[':
				depth++
			case ']':
				depth--
			case '=':
				if depth == 0 {
					equal = i
				}
			}
			if equal >= 0 {
				break
			}
		}
		key := segment
		var value *string
		if equal >= 0 {
			key = segment[:equal]
			text := resolvePlaceholders(segment[equal+1:], extracted)
			text = strings.TrimSpace(trimWrappedBracketKey(text))
			value = &text
		}
		keys := appendBracketSegment(nil, strings.TrimSpace(key), extracted, unquoteWrappedBracketKey)
		for i, key := range keys {
			selector := sourceSelector{key: key}
			if i == len(keys)-1 {
				selector.value = value
				if value != nil && !strings.HasPrefix(segment[equal+1:], "{{") {
					selector.literal = key + "=" + *value
					selector.remaining = restored[segmentIndex+1:]
				}
			}
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

// ResolveSourcePath checks typed traversal against the same input evaluated by
// the rule. A missing final object property locates its existing parent.
func ResolveSourcePath(root SourceValue, path model.SourcePath) (model.SourcePath, error) {
	current := root
	for index, segment := range path {
		switch current.Kind() {
		case reflect.Map:
			if segment.IsIndex {
				return nil, fmt.Errorf("array index applied to object")
			}
			next, found := current.Field(segment.Key)
			if !found {
				if index == len(path)-1 {
					return path[:index], nil
				}
				return nil, fmt.Errorf("missing intermediate source property")
			}
			current = next
		case reflect.Slice:
			if !segment.IsIndex {
				return nil, fmt.Errorf("object key applied to array")
			}
			if segment.Index < 0 || segment.Index >= current.Length() {
				return nil, fmt.Errorf("array index out of bounds")
			}
			current = current.Element(segment.Index)
		default:
			return nil, fmt.Errorf("source traversal through scalar unsupported")
		}
	}
	return path, nil
}

// ResolveLegacySourcePath preserves value selectors until their concrete
// object/array occurrence is known, then returns a typed source address.
func ResolveLegacySourcePath(ctx context.Context, root SourceValue, key string) (model.SourcePath, error) {
	current := root
	var path model.SourcePath
	selectors := sourceSelectors(key)
	for index, selector := range selectors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		selector = preferLiteralSourceSelector(current, selector)
		if selector.value != nil {
			match := resolveSourceAnchor(ctx, current, selector, path, index == len(selectors)-1)
			if !match.found {
				return nil, fmt.Errorf("source value selector did not match")
			}
			if match.terminal || index == len(selectors)-1 {
				return match.memberPath, nil
			}
			current = match.parent
			path = match.parentPath
			continue
		}
		if current.Kind() == reflect.Slice {
			item, err := strconv.Atoi(selector.key)
			if err != nil || item < 0 || item >= current.Length() {
				return nil, fmt.Errorf("invalid source array index")
			}
			path = append(path, model.PathSegment{Index: item, IsIndex: true})
			current = current.Element(item)
			continue
		}
		next, found := current.Field(selector.key)
		if current.Kind() != reflect.Map {
			return nil, fmt.Errorf("source traversal through scalar unsupported")
		}
		if !found {
			parent, _, memberPath, ok := newSourceMemberFinder(ctx, selector.key, nil).find(current, path)
			if !ok {
				if index == len(selectors)-1 {
					return path, nil
				}
				return nil, fmt.Errorf("source property did not match")
			}
			path = memberPath
			current, _ = parent.Field(selector.key)
			continue
		}
		path = append(path, model.PathSegment{Key: selector.key})
		current = next
	}
	return path, nil
}

func preferLiteralSourceSelector(node SourceValue, selector sourceSelector) sourceSelector {
	if selector.literal != "" {
		if _, found := node.Field(selector.literal); found {
			return sourceSelector{key: selector.literal}
		}
	}
	return selector
}

type sourceAnchorMatch struct {
	parent                 SourceValue
	parentPath, memberPath model.SourcePath
	found, terminal        bool
}

func resolveSourceAnchor(
	ctx context.Context, node SourceValue, selector sourceSelector, path model.SourcePath, terminal bool,
) sourceAnchorMatch {
	for _, partial := range []bool{false, true} {
		if len(selector.remaining) > 0 {
			full := *selector.value + "." + strings.Join(selector.remaining, ".")
			parent, parentPath, memberPath, found := newSourceMemberFinder(ctx, selector.key, &full).findMode(node, path, partial)
			if found {
				return sourceAnchorMatch{parent, parentPath, memberPath, true, true}
			}
		}
		parent, parentPath, memberPath, found := newSourceMemberFinder(ctx, selector.key, selector.value).findMode(node, path, partial)
		if found {
			return sourceAnchorMatch{parent, parentPath, memberPath, true, false}
		}
	}
	if terminal && selector.literal != "" && ctx.Err() == nil {
		return sourceAnchorMatch{node, path, path, true, true}
	}
	return sourceAnchorMatch{}
}

// The search and matching caches are per selector. Shared YAML subtrees are
// visited once even when many jobs reference the same array or mapping.
type sourceMemberFinder struct {
	ctx      context.Context
	key      string
	expected *string
	seen     map[SourceIdentity]bool
	matches  map[SourceIdentity]sourceValueMatch
	partial  bool
}
type sourceValueMatch struct {
	suffix model.SourcePath
	found  bool
}

func newSourceMemberFinder(ctx context.Context, key string, expected *string) *sourceMemberFinder {
	return &sourceMemberFinder{ctx: ctx, key: key, expected: expected}
}
func appendSourcePath(path model.SourcePath, parts ...model.PathSegment) model.SourcePath {
	out := make(model.SourcePath, 0, len(path)+len(parts))
	out = append(out, path...)
	return append(out, parts...)
}
func sourceChildKeys(node SourceValue) []model.PathSegment {
	switch node.Kind() {
	case reflect.Map:
		keys := node.Keys()
		_, written := node.(writtenSourceValue)
		out := make([]model.PathSegment, 0, len(keys))
		for _, key := range keys {
			if (written || !sourceBookkeeping(node, key)) && !sourceScriptMetadata(node, key) {
				out = append(out, model.PathSegment{Key: key})
			}
		}
		return out
	case reflect.Slice:
		out := make([]model.PathSegment, node.Length())
		for index := range out {
			out[index] = model.PathSegment{Index: index, IsIndex: true}
		}
		return out
	default:
		return nil
	}
}
func sourceBookkeeping(node SourceValue, key string) bool {
	if key == lineInfoKey {
		return true
	}
	if key != sourcePathKey && key != sourceDocumentIDKey {
		return false
	}
	child, _ := node.Field(key)
	return child.Kind() != reflect.Map
}

func sourceScriptMetadata(node SourceValue, key string) bool {
	if !strings.HasPrefix(key, "_parsed_") {
		return false
	}
	_, hasSource := node.Field(strings.TrimPrefix(key, "_parsed_"))
	if !hasSource {
		return false
	}
	value, _ := node.Field(key)
	if value.Kind() != reflect.Map {
		return true
	}
	for _, field := range []string{"script", "run", "trigger", "extends"} {
		if _, job := value.Field(field); job {
			return false
		}
	}
	_, commands := value.Field("commands")
	_, parsed := value.Field("parse_ok")
	return commands && parsed
}

func sourceChild(node SourceValue, part model.PathSegment) SourceValue {
	if part.IsIndex {
		return node.Element(part.Index)
	}
	child, _ := node.Field(part.Key)
	return child
}
func (f *sourceMemberFinder) member(node SourceValue, path model.SourcePath) (model.SourcePath, bool) {
	value, ok := node.Field(f.key)
	if !ok {
		return nil, false
	}
	member := appendSourcePath(path, model.PathSegment{Key: f.key})
	if f.expected == nil {
		return member, true
	}
	match := f.match(value)
	return appendSourcePath(member, match.suffix...), match.found
}
func (f *sourceMemberFinder) find(
	node SourceValue, path model.SourcePath,
) (parent SourceValue, parentPath, memberPath model.SourcePath, found bool) {
	for _, partial := range []bool{false, true} {
		parent, parentPath, memberPath, found = f.findMode(node, path, partial)
		if found || f.expected == nil || f.ctx.Err() != nil {
			return
		}
	}
	return
}

func (f *sourceMemberFinder) findMode(
	node SourceValue, path model.SourcePath, partial bool,
) (parent SourceValue, parentPath, memberPath model.SourcePath, found bool) {
	f.partial = partial
	f.seen = make(map[SourceIdentity]bool)
	f.matches = make(map[SourceIdentity]sourceValueMatch)
	return f.search(node, path)
}

func (f *sourceMemberFinder) search(
	node SourceValue, path model.SourcePath,
) (parent SourceValue, parentPath, memberPath model.SourcePath, found bool) {
	if f.ctx.Err() != nil {
		return nil, nil, nil, false
	}
	if id := node.Identity(); id.Pointer != 0 {
		if f.seen[id] {
			return nil, nil, nil, false
		}
		f.seen[id] = true
	}
	if member, ok := f.member(node, path); ok {
		return node, appendSourcePath(path), member, true
	}
	for _, part := range sourceChildKeys(node) {
		child := sourceChild(node, part)
		if found, parent, member, ok := f.search(child, append(path, part)); ok {
			return found, parent, member, true
		}
	}
	return nil, nil, nil, false
}
func (f *sourceMemberFinder) match(value SourceValue) sourceValueMatch {
	if f.ctx.Err() != nil {
		return sourceValueMatch{}
	}
	if value.Kind() == reflect.Invalid {
		text := value.Text()
		return sourceValueMatch{found: text == *f.expected || (f.partial && *f.expected != "" && strings.Contains(text, *f.expected))}
	}
	id := value.Identity()
	if cached, seen := f.matches[id]; seen {
		return cached
	}
	f.matches[id] = sourceValueMatch{}
	for _, part := range sourceChildKeys(value) {
		if child := f.match(sourceChild(value, part)); child.found {
			found := sourceValueMatch{suffix: appendSourcePath(model.SourcePath{part}, child.suffix...), found: true}
			f.matches[id] = found
			return found
		}
	}
	return sourceValueMatch{}
}
