package detector

import (
	"context"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	yamlparser "github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml"
	"gopkg.in/yaml.v3"
)

// metadataKey is the Kustomize metadata field name used by writer targeting
// and document selection.
const metadataKey = "metadata"

// templateScope and selectorScope name the parts of a resource a label or
// annotation path can point at beyond its own metadata, and testOp is the
// JSON 6902 op that only asserts a value.
const (
	templateScope = "template"
	selectorScope = "selector"
	testOp        = "test"
)

// KustomizeDetectLine finds the line of a finding raised on a document
// Kustomize rendered, in the file it was rendered from. Search keys name the
// rendered resource; they are rewritten to its name and namespace as written.
// A generated object is reported on its generator entry, whose line alone is
// shown so that generator literals never reach the output.
type KustomizeDetectLine struct{}

// DetectLine resolves the vulnerability line for a finding.
func (KustomizeDetectLine) DetectLine(ctx context.Context, file *model.FileMetadata, searchKey string,
	outputLines int) model.VulnerabilityLines {
	a := file.Kustomize
	if a == nil {
		return defaultDetectLine{}.DetectLine(ctx, file, searchKey, outputLines)
	}
	if a.Generator != nil {
		return generatorLine(file, a)
	}
	key := SourceSearchKey(a, searchKey)
	var src *model.VulnerabilityLines
	source := func() model.VulnerabilityLines {
		if src == nil {
			v := detectSourceLine(ctx, file, key, outputLines, a.SourceDocumentIndex)
			src = &v
		}
		return *src
	}
	if got, ok := detectWriter(ctx, file, a, searchKey, outputLines, source); ok {
		return got
	}
	return source()
}

// SourceSearchKey rewrites the rendered metadata name and namespace of a's
// resource in searchKey to the ones written in its source file; other values
// that happen to equal them, such as a container name, are left alone.
func SourceSearchKey(a *model.KustomizeAttribution, searchKey string) string {
	if a.SourceName != "" && a.RenderedName != a.SourceName {
		searchKey = strings.ReplaceAll(searchKey, "metadata.name={{"+a.RenderedName+"}}", "metadata.name={{"+a.SourceName+"}}")
	}
	if a.RenderedNamespace != "" && a.SourceNamespace != "" && a.RenderedNamespace != a.SourceNamespace {
		searchKey = strings.ReplaceAll(searchKey, "metadata.namespace={{"+a.RenderedNamespace+"}}",
			"metadata.namespace={{"+a.SourceNamespace+"}}")
	}
	return searchKey
}

func generatorLine(file *model.FileMetadata, a *model.KustomizeAttribution) model.VulnerabilityLines {
	// The generator entry is found structurally (any YAML style), and the
	// shown text is the entry's name alone: generator literals never reach
	// the output, not even on a flow-style line.
	line := generatorEntryLine(file.OriginalData, a.Generator.Name)
	if line <= 0 {
		line = 1
	}
	text := "name: " + a.Generator.Name
	loc := model.ResourceLocation{
		Start: model.ResourceLine{Line: line, Col: 1},
		End:   model.ResourceLine{Line: line, Col: len(text) + 1},
	}
	return model.VulnerabilityLines{
		Line:                   line,
		VulnLines:              &[]model.CodeLine{{Position: line, Line: text}},
		LineWithVulnerability:  text,
		ResolvedFile:           file.FilePath,
		VulnerablilityLocation: loc,
		RemediationLocation:    loc,
		BlockLocation:          loc,
		ResourceSource:         text,
		FileSource:             []string{text},
	}
}

// detectSourceLine scopes the text search to the document the resource was
// rendered from, so a same-name document of another kind cannot win, and
// translates the offsets back to the whole file.
func detectSourceLine(ctx context.Context, file *model.FileMetadata, key string,
	outputLines, docIndex int) model.VulnerabilityLines {
	if docIndex < 0 {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	start, end, ok := documentSpan(file.OriginalData, docIndex)
	if !ok {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	lines := file.Lines()
	if start < 1 || end > len(lines) || start > end {
		return defaultDetectLine{}.DetectLine(ctx, file, key, outputLines)
	}
	span := append([]string(nil), lines[start-1:end]...)
	sub := &model.FileMetadata{FilePath: file.FilePath, OriginalData: strings.Join(span, "\n"), Kind: file.Kind}
	sub.LinesOriginalData = &span
	got := defaultDetectLine{}.DetectLine(ctx, sub, key, outputLines)
	if got.Line < 1 {
		// The mapped document does not hold the key: report nothing rather
		// than a line from another document of the same file.
		return got
	}
	shift(&got, start-1)
	return got
}

// documentSpan returns the 1-based start and end lines of the index-th
// document of a multi-document YAML file: each document ends where the next
// one starts, not at EOF. Empty and comment-only documents are skipped, as
// the YAML parser does when it indexes documents.
func documentSpan(content string, index int) (start, end int, ok bool) {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var starts []int
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		if !yamlparser.IsEmptyDocument(&doc) {
			starts = append(starts, doc.Line)
		}
	}
	if index < 0 || index >= len(starts) {
		return 0, 0, false
	}
	start = starts[index]
	if start < 1 {
		start = 1
	}
	end = strings.Count(content, "\n") + 1
	if index+1 < len(starts) && starts[index+1] > start {
		end = starts[index+1] - 1
	}
	return start, end, true
}

// generatorEntryLine is the 1-based line of the generator entry named name in
// a kustomization, in any YAML style.
func generatorEntryLine(content, name string) int {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || len(doc.Content) == 0 {
		return 0
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return 0
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		section := root.Content[i+1]
		if root.Content[i].Value != "configMapGenerator" && root.Content[i].Value != "secretGenerator" {
			continue
		}
		if section.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range section.Content {
			for k := 0; k+1 < len(item.Content); k += 2 {
				if item.Content[k].Value == "name" && item.Content[k+1].Value == name {
					return item.Line
				}
			}
		}
	}
	return 0
}

// detectWriter returns the line of the last patch or transformer entry that
// set the field searchKey names, if any.
func detectWriter(ctx context.Context, file *model.FileMetadata, a *model.KustomizeAttribution, searchKey string,
	outputLines int, source func() model.VulnerabilityLines) (model.VulnerabilityLines, bool) {
	segs := splitSearchKey(searchKey)
	if len(segs) == 0 {
		return model.VulnerabilityLines{}, false
	}
	last := segs[len(segs)-1]
	for i := range a.Writers {
		w := &a.Writers[i]
		if got, ok := writerLine(ctx, w, a, file, searchKey, segs, last, i, outputLines, source); ok {
			return got, true
		}
	}
	return model.VulnerabilityLines{}, false
}

// writerLine resolves the line one writer contributed for the field segs
// names, if any.
func writerLine(ctx context.Context, w *model.KustomizeWriter, a *model.KustomizeAttribution,
	file *model.FileMetadata, searchKey string, segs []string, last string, i, outputLines int,
	source func() model.VulnerabilityLines) (model.VulnerabilityLines, bool) {
	switch w.Kind {
	case model.KustomizeStrategicMerge:
		return smpWriterLine(ctx, w, a, searchKey, segs, outputLines)
	case model.KustomizeJSON6902:
		if l := jsonOpLine(w.Content, segs); l > 0 {
			return lineIn(w.File, w.Content, l+w.LineOffset, l), true
		}
	default:
		return transformerWriterLine(w, a, file, segs, last, i, source)
	}
	return model.VulnerabilityLines{}, false
}

// smpWriterLine reports the line of an SMP patch that set the field segs
// names, shifted to its position in the kustomization file.
func smpWriterLine(ctx context.Context, w *model.KustomizeWriter, a *model.KustomizeAttribution,
	searchKey string, segs []string, outputLines int) (model.VulnerabilityLines, bool) {
	name, docIndex, ok := smpWrites(w.Content, w, a, segs)
	if !ok {
		return model.VulnerabilityLines{}, false
	}
	// Only the resource's name anchor is rewritten: a container or other
	// value that happens to equal the rendered name keeps its own.
	key := strings.ReplaceAll(searchKey, metadataKey+".name={{"+a.RenderedName+"}}", metadataKey+".name={{"+name+"}}")
	patch := &model.FileMetadata{FilePath: w.File, OriginalData: w.Content, Kind: model.KindYAML}
	by := w.LineOffset
	// The search stays inside the document smpWrites selected: a same-name
	// document of another kind or namespace must not win.
	if start, end, ok := documentSpan(w.Content, docIndex); ok {
		lines := patch.Lines()
		if start >= 1 && end <= len(lines) && start <= end {
			span := append([]string(nil), lines[start-1:end]...)
			patch.OriginalData = strings.Join(span, "\n")
			patch.LinesOriginalData = &span
			by += start - 1
		}
	}
	got := defaultDetectLine{}.DetectLine(ctx, patch, key, outputLines)
	if got.Line < 1 {
		return model.VulnerabilityLines{}, false
	}
	shift(&got, by)
	return got, true
}

// transformerWriterLine reports the line of a builtin transformer entry
// (images, namespace, replicas) that set the field segs names.
func transformerWriterLine(w *model.KustomizeWriter, a *model.KustomizeAttribution, file *model.FileMetadata,
	segs []string, last string, i int, source func() model.VulnerabilityLines) (model.VulnerabilityLines, bool) {
	switch w.Kind {
	case model.KustomizeImages:
		if last != "image" {
			return model.VulnerabilityLines{}, false
		}
		// The entry matches the image the resource carries when it applies,
		// which the patches and entries applied before it may have renamed;
		// a JSON patch writing the image by a list index leaves it unproven.
		if visible, known := visibleImage(a.Writers, i, a, segs, imageName(lineText(file, source().Line))); !known || visible != w.Name {
			return model.VulnerabilityLines{}, false
		}
		return lineIn(w.File, "", w.Line, 0), true
	case model.KustomizeNamespace:
		if last == "namespace" && len(segs) >= 2 && segs[len(segs)-2] == metadataKey {
			return lineIn(w.File, "", w.Line, 0), true
		}
	case model.KustomizeReplicas:
		if last == "replicas" && len(segs) >= 2 && segs[len(segs)-2] == "spec" {
			return lineIn(w.File, "", w.Line, 0), true
		}
	case model.KustomizeLabels, model.KustomizeAnnotations:
		return kvEntryLine(w, segs, last)
	case model.KustomizeReplacement:
		// Replacements are not attributed yet; never guessed.
	}
	return model.VulnerabilityLines{}, false
}

// kvEntryLine reports the line of a label or annotation transformer entry
// whose keys the search key names. The key's path must name the entry's
// category right before its final key, and the path's scope must be one the
// entry reaches: the resource's own metadata always, pod templates and
// selectors only when the entry propagates there.
func kvEntryLine(w *model.KustomizeWriter, segs []string, last string) (model.VulnerabilityLines, bool) {
	category := "labels"
	if w.Kind == model.KustomizeAnnotations {
		category = "annotations"
	}
	if len(segs) < 2 || segs[len(segs)-2] != category || !keysContain(w.Name, last) {
		return model.VulnerabilityLines{}, false
	}
	switch labelScope(segs[:len(segs)-2]) {
	case templateScope:
		if !w.Templates {
			return model.VulnerabilityLines{}, false
		}
	case selectorScope:
		if !w.Selectors {
			return model.VulnerabilityLines{}, false
		}
	case metadataKey:
	default:
		// An unknown scope is unproven: the source keeps the line.
		return model.VulnerabilityLines{}, false
	}
	return lineIn(w.File, "", w.Line, 0), true
}

// labelScope classifies where in the resource a label or annotation path
// points, after the resource's name anchor: "metadata", "template",
// "selector", or "" for anything unproven.
func labelScope(segs []string) string {
	path := segs
	if len(path) >= 2 && path[0] == metadataKey && strings.HasPrefix(path[1], "name=") {
		path = path[2:]
	}
	for _, s := range path {
		if s == templateScope {
			return templateScope
		}
		if s == selectorScope {
			return selectorScope
		}
	}
	if len(path) > 0 && path[len(path)-1] == metadataKey {
		return metadataKey
	}
	return ""
}

// keysContain reports whether the comma-joined keys include key.
func keysContain(joined, key string) bool {
	for _, k := range strings.Split(joined, ",") {
		if k == key {
			return true
		}
	}
	return false
}

// imageName is the image name of an "image:" line, without tag or digest.
func imageName(line string) string {
	_, ref, _ := strings.Cut(line, "image:")
	return imageRef(ref)
}

// imageRef is an image reference without tag or digest.
func imageRef(ref string) string {
	ref = strings.Trim(strings.TrimSpace(ref), `"'`)
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

func lineText(file *model.FileMetadata, line int) string {
	lines := file.Lines()
	if line >= 1 && line <= len(lines) {
		return lines[line-1]
	}
	return ""
}

// visibleImage returns the image name the resource carries when writers[i]
// applies, and whether it is known: the source image as the patches and
// images entries applied before it reshaped it. Writers are last applied
// first, so those are the ones after i, and an entry whose name does not
// match changes nothing. A JSON patch writing the image by a list index
// leaves it unproven, since the index cannot be tied to the container, and
// a later patch setting the image exactly proves it again.
func visibleImage(writers []model.KustomizeWriter, i int, a *model.KustomizeAttribution,
	segs []string, source string) (string, bool) {
	cur := source
	known := true
	for j := len(writers) - 1; j > i; j-- {
		switch w := &writers[j]; w.Kind {
		case model.KustomizeImages:
			if known && w.Name == cur && w.NewName != "" {
				cur = w.NewName
			}
		case model.KustomizeStrategicMerge:
			img, ok := patchedImage(w, a, segs)
			if ok {
				cur, known = img, true
			}
		case model.KustomizeJSON6902:
			if jsonOpTouchesField(w.Content, segs) {
				known = false
			}
		}
	}
	return cur, known
}

// jsonOpTouchesField reports whether a writing op of a JSON 6902 patch may
// set the field the search key names: its path matches the key's, with the
// key's value anchors matching any list index the op names.
func jsonOpTouchesField(content string, segs []string) bool {
	if len(segs) >= 2 && segs[0] == metadataKey && strings.HasPrefix(segs[1], "name=") {
		segs = segs[2:]
	}
	if len(segs) == 0 {
		return false
	}
	var seq yaml.Node
	if err := yaml.Unmarshal([]byte(content), &seq); err != nil || len(seq.Content) == 0 {
		return false
	}
	root := seq.Content[0]
	if root.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range root.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		op, p, line := jsonOp(item)
		if op == testOp || line <= 0 {
			continue
		}
		if opTouches(strings.Split(strings.TrimPrefix(p, "/"), "/"), segs) {
			return true
		}
	}
	return false
}

// opTouches reports whether the op path's segments match the key's, with a
// value anchor of the key matching any single segment.
func opTouches(op, keys []string) bool {
	if len(op) > len(keys) {
		return false
	}
	for i, o := range op {
		if keys[i] != o && !strings.Contains(keys[i], "=") {
			return false
		}
	}
	return true
}

// patchedImage returns the image name an SMP patch writes for the container
// the search key names, if it sets it.
func patchedImage(w *model.KustomizeWriter, a *model.KustomizeAttribution, segs []string) (string, bool) {
	_, _, value, ok := smpDoc(w.Content, w, a, segs)
	if !ok {
		return "", false
	}
	if img := imageRef(toString(value)); img != "" {
		return img, true
	}
	return "", false
}

// lineIn reports line of file; text is shown from content's contentLine
// when given.
func lineIn(file, content string, line, contentLine int) model.VulnerabilityLines {
	text := ""
	if content != "" {
		if ls := strings.Split(content, "\n"); contentLine >= 1 && contentLine <= len(ls) {
			text = ls[contentLine-1]
		}
	}
	loc := model.ResourceLocation{Start: model.ResourceLine{Line: line, Col: 1}, End: model.ResourceLine{Line: line, Col: len(text) + 1}}
	return model.VulnerabilityLines{
		Line: line, VulnLines: &[]model.CodeLine{{Position: line, Line: text}}, LineWithVulnerability: text,
		ResolvedFile: file, VulnerablilityLocation: loc, RemediationLocation: loc, BlockLocation: loc,
	}
}

func shift(v *model.VulnerabilityLines, by int) {
	if by == 0 {
		return
	}
	v.Line += by
	v.VulnerablilityLocation.Start.Line += by
	v.VulnerablilityLocation.End.Line += by
	v.RemediationLocation.Start.Line += by
	v.RemediationLocation.End.Line += by
	v.BlockLocation.Start.Line += by
	v.BlockLocation.End.Line += by
	if v.VulnLines != nil {
		shifted := make([]model.CodeLine, len(*v.VulnLines))
		for i, l := range *v.VulnLines {
			l.Position += by
			shifted[i] = l
		}
		v.VulnLines = &shifted
	}
}

// splitSearchKey splits a search key on the dots outside {{ }}.
func splitSearchKey(key string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(key); i++ {
		switch {
		case strings.HasPrefix(key[i:], "{{"):
			depth++
			i++
		case strings.HasPrefix(key[i:], "}}") && depth > 0:
			depth--
			i++
		case key[i] == '.' && depth == 0:
			out = append(out, key[start:i])
			start = i + 1
		}
	}
	return append(out, key[start:])
}

// smpWrites reports the document of a strategic-merge patch that targets a's
// resource and holds the path segs names, with its index and name. A patch
// entry with an explicit target was already selected by it when the writer
// was recorded, so a document whose own name differs still applies.
func smpWrites(content string, w *model.KustomizeWriter, a *model.KustomizeAttribution,
	segs []string) (name string, docIndex int, ok bool) {
	name, docIndex, _, ok = smpDoc(content, w, a, segs)
	return name, docIndex, ok
}

// smpDoc reports the document of a strategic-merge patch that targets a's
// resource and sets the field segs names, with its index, name and the value
// it sets. A patch entry with an explicit target was already selected by it
// when the writer was recorded, so a document whose own name differs still
// applies.
func smpDoc(content string, w *model.KustomizeWriter, a *model.KustomizeAttribution,
	segs []string) (name string, docIndex int, value interface{}, ok bool) {
	dec := yaml.NewDecoder(strings.NewReader(content))
	fallbackName, fallbackIndex, fallbackValue := "", -1, interface{}(nil)
	for i := 0; ; i++ {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			break
		}
		// Documents are indexed as documentSpan indexes them.
		if yamlparser.IsEmptyDocument(&node) {
			i--
			continue
		}
		var doc map[string]interface{}
		if node.Decode(&doc) != nil {
			continue
		}
		docName, docValue, targets := smpTargets(doc, w, a, segs)
		if !targets {
			continue
		}
		if docName == a.SourceName || docName == a.RenderedName ||
			(strings.Contains(a.RenderedName, docName) && strings.Contains(docName, a.SourceName)) {
			return docName, i, docValue, true
		}
		if w.Targeted && fallbackIndex < 0 {
			fallbackName, fallbackIndex, fallbackValue = docName, i, docValue
		}
	}
	return fallbackName, fallbackIndex, fallbackValue, fallbackIndex >= 0
}

// smpTargets reports whether one patch document targets a's resource and
// sets the field segs names, with the document's name and the value it sets.
func smpTargets(doc map[string]interface{}, w *model.KustomizeWriter, a *model.KustomizeAttribution,
	segs []string) (name string, value interface{}, ok bool) {
	kind, _ := doc["kind"].(string)
	meta, _ := doc[metadataKey].(map[string]interface{})
	docName, _ := meta["name"].(string)
	if kind != a.Kind {
		return "", nil, false
	}
	// A document naming another namespace does not target the resource; an
	// explicit target was already checked against it when recorded.
	if ns, _ := meta["namespace"].(string); !w.Targeted && ns != "" &&
		ns != a.SourceNamespace && ns != a.RenderedNamespace {
		return "", nil, false
	}
	path := segs
	// The document is already selected by its name.
	if len(path) >= 2 && path[0] == metadataKey && strings.HasPrefix(path[1], "name=") {
		path = path[2:]
	}
	if len(path) == 0 {
		return "", nil, false
	}
	// A writer owns a key only when it sets the field the key names, as a
	// scalar. A key stopping at an element of a list, or at an object the
	// patch merely holds, anchors a finding on a field that is still
	// missing.
	fieldValue, ok := smpTargetField(doc, path)
	if !ok {
		return "", nil, false
	}
	return docName, fieldValue, true
}

// smpTargetField reports the scalar value a patch document sets for the
// field the terminal segment of path names. A key stopping at an element of
// a list, or at an object the patch merely holds, sets nothing.
func smpTargetField(doc map[string]interface{}, path []string) (interface{}, bool) {
	parent, ok := hasPath(doc, path[:len(path)-1])
	if !ok {
		return nil, false
	}
	fields, ok := parent.(map[string]interface{})
	if !ok {
		return nil, false
	}
	if k, v, isAnchor := strings.Cut(path[len(path)-1], "="); isAnchor {
		v = strings.TrimSuffix(strings.TrimPrefix(v, "{{"), "}}")
		if toString(fields[k]) != v {
			return nil, false
		}
		return fields[k], true
	}
	value, ok := fields[path[len(path)-1]]
	if !ok {
		return nil, false
	}
	switch value.(type) {
	case map[string]interface{}, []interface{}:
		return nil, false
	}
	return value, true
}

// hasPath walks segs through doc and returns the node it reaches. A segment
// "k={{v}}" selects the list element whose k is v, or, on a mapping whose k
// is v, keeps its parent.
func hasPath(doc interface{}, segs []string) (interface{}, bool) {
	stack := []interface{}{doc}
	cur := doc
	for _, s := range segs {
		if k, v, ok := strings.Cut(s, "="); ok {
			v = strings.TrimSuffix(strings.TrimPrefix(v, "{{"), "}}")
			switch node := cur.(type) {
			case []interface{}:
				found := false
				for _, e := range node {
					if m, ok := e.(map[string]interface{}); ok && toString(m[k]) == v {
						stack, cur, found = append(stack, m), m, true
						break
					}
				}
				if !found {
					return nil, false
				}
			case map[string]interface{}:
				if toString(node[k]) != v {
					return nil, false
				}
				if len(stack) > 1 {
					stack = stack[:len(stack)-1]
					cur = stack[len(stack)-1]
				}
			default:
				return nil, false
			}
			continue
		}
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, ok := m[s]
		if !ok {
			return nil, false
		}
		stack, cur = append(stack, next), next
	}
	return cur, true
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

// jsonOpLine returns the line of the "path:" of the last writing op of a
// JSON 6902 patch whose path covers the field segs names.
func jsonOpLine(content string, segs []string) int {
	// Drop the "metadata.name=…" anchor, which selects the document.
	if len(segs) >= 2 && segs[0] == metadataKey && strings.HasPrefix(segs[1], "name=") {
		segs = segs[2:]
	}
	if len(segs) == 0 {
		return 0
	}
	var seq yaml.Node
	if err := yaml.Unmarshal([]byte(content), &seq); err != nil || len(seq.Content) == 0 {
		return 0
	}
	root := seq.Content[0]
	if root.Kind != yaml.SequenceNode {
		return 0
	}
	// Structural parsing covers YAML lists and JSON arrays alike; the last
	// matching op wins, as the last writer.
	best := 0
	for _, item := range root.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		op, p, line := jsonOp(item)
		// A test op asserts a value without writing it: it never owns a field.
		if op == testOp || line <= 0 {
			continue
		}
		if opCovers(strings.Split(strings.TrimPrefix(p, "/"), "/"), segs) {
			best = line
		}
	}
	return best
}

// jsonOp returns the op, the path and the path's line of one JSON 6902 op.
func jsonOp(item *yaml.Node) (op, path string, line int) {
	for k := 0; k+1 < len(item.Content); k += 2 {
		switch item.Content[k].Value {
		case "path":
			path = strings.Trim(item.Content[k+1].Value, `"'`)
			line = item.Content[k+1].Line
		case "op":
			op = strings.Trim(item.Content[k+1].Value, `"'`)
		}
	}
	return op, path, line
}

// opCovers reports whether the op path's segments are a prefix of the field
// path the search key names. A list index in an op path can never be proven
// to select the element an anchor names, so the segments must match exactly.
func opCovers(op, keys []string) bool {
	if len(op) > len(keys) {
		return false
	}
	for i, o := range op {
		if keys[i] != o {
			return false
		}
	}
	return true
}
