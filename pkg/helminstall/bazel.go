/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package helminstall

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// Bazel BUILD files declare charts, the bundles packaging them and their
// installations, often through loops and string formatting over settings
// loaded from .bzl files. They are evaluated as Starlark: every rule or macro
// they call that the repository does not define stands for one recording its
// arguments as a target, an in-repository load is evaluated, and a value from
// an external repository is a placeholder.
//
// A target whose files include a Chart.yaml is a chart. A rule installing,
// releasing or deploying, which reaches a chart through its chart, bundle or
// actual attributes, is an installation of it. Its release name and namespace
// are its release_name and namespace attributes, or come from its name
// <release>.<namespace>.<cluster>.<datacenter>, the convention of Datadog
// CNAB tools, which also apply the values/environments files of the chart
// matching that name.

const (
	// maxBazelSteps bounds the Starlark steps of one BUILD or .bzl file, and
	// maxBazelFileTime the time its evaluation takes.
	maxBazelSteps    = 20_000_000
	maxBazelFileTime = 5 * time.Second
	// maxLabelDepth bounds how far labels are followed from a target.
	maxLabelDepth = 6
	// maxBazelFiles bounds the BUILD and .bzl files evaluated.
	maxBazelFiles = 20_000
)

const (
	buildFileName      = "BUILD"
	buildBazelFileName = "BUILD.bazel"
	// valuesStrategyMerge is the CNAB values strategy keeping the environment
	// files under values files.
	valuesStrategyMerge = "merge"
)

var bazelFileOptions = &syntax.FileOptions{
	Set: true, While: true, TopLevelControl: true, GlobalReassign: true, Recursion: true,
}

func isBazelFile(base string) bool {
	switch base {
	case buildFileName, buildBazelFileName, "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel":
		return true
	}
	return strings.HasSuffix(base, ".bzl")
}

// bazelTarget is a rule or macro call a BUILD file makes.
type bazelTarget struct {
	kind  string
	name  string
	attrs map[string]interface{}
	pkg   *bazelPackage
}

// bazelPackage is an evaluated BUILD file.
type bazelPackage struct {
	// workspace is the root of the workspace, dir the package's directory and
	// name its path from the workspace root.
	workspace, dir, name string
	targets              map[string]*bazelTarget
	order                []*bazelTarget
}

type bazelModule struct {
	globals starlark.StringDict
	err     error
}

// bazelEval evaluates the BUILD and .bzl files of a scan.
type bazelEval struct {
	d          *discovery
	packages   map[string]*bazelPackage
	modules    map[string]*bazelModule
	workspaces map[string]string
	listings   map[string][]string
	// evaluated counts the files run.
	evaluated int
	// fileMemo and chartMemo memoize what labels and targets lead to, so that
	// a label many targets list is followed once.
	fileMemo  map[fileKey][]string
	chartMemo map[*bazelTarget]chartResult
}

// fileKey is a label as a package reads it.
type fileKey struct {
	pkg   *bazelPackage
	label string
}

type chartResult struct {
	dir string
	ok  bool
}

func newBazelEval(d *discovery) *bazelEval {
	return &bazelEval{
		d: d, packages: map[string]*bazelPackage{}, modules: map[string]*bazelModule{},
		workspaces: map[string]string{}, listings: map[string][]string{},
		fileMemo: map[fileKey][]string{}, chartMemo: map[*bazelTarget]chartResult{},
	}
}

func (d *discovery) bazel(files []string) {
	ev := d.bazelEvaluator()
	var builds []string
	for _, f := range files {
		base := filepath.Base(f)
		if base != buildFileName && base != buildBazelFileName {
			continue
		}
		data := d.read(f)
		if data == nil || !mentionsHelm(data) {
			continue
		}
		builds = append(builds, filepath.Dir(f))
	}
	sort.Strings(builds)
	for _, dir := range builds {
		ev.pkg(dir)
	}
	for _, dir := range builds {
		pkg := ev.packages[dir]
		if pkg == nil {
			continue
		}
		for _, t := range pkg.order {
			ev.installation(t)
		}
	}
}

// helmMentions are what a BUILD file mentioning a chart or its installation
// holds.
var helmMentions = regexp.MustCompile(`(?i)helm|cnab|chart\.yaml`)

func mentionsHelm(data []byte) bool {
	return helmMentions.Match(data)
}

// workspaceOf returns the root of the workspace holding dir: the nearest
// directory above with a WORKSPACE or MODULE.bazel, the repository root when
// none is found.
func (ev *bazelEval) workspaceOf(dir string) string {
	if ws, ok := ev.workspaces[dir]; ok {
		return ws
	}
	ws := ev.d.idx.root
	for cur := dir; ; {
		found := false
		for _, marker := range []string{"MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"} {
			if fileExists(ev.d.fsys(), filepath.Join(cur, marker)) {
				found = true
				break
			}
		}
		if found {
			ws = cur
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur || cur == ev.d.idx.root {
			break
		}
		cur = parent
	}
	ev.workspaces[dir] = ws
	return ws
}

// buildFile returns the BUILD file of the package at dir.
func (ev *bazelEval) buildFile(dir string) (string, bool) {
	for _, name := range []string{buildBazelFileName, buildFileName} {
		if p := filepath.Join(dir, name); fileExists(ev.d.fsys(), p) {
			return p, true
		}
	}
	return "", false
}

// pkg evaluates the package at dir once, nil when it has no BUILD file.
func (ev *bazelEval) pkg(dir string) *bazelPackage {
	dir = filepath.Clean(dir)
	if p, ok := ev.packages[dir]; ok {
		return p
	}
	if !ev.d.idx.confined(dir) {
		return nil
	}
	ev.packages[dir] = nil
	file, ok := ev.buildFile(dir)
	if !ok {
		return nil
	}
	src := ev.d.read(file)
	if src == nil {
		return nil
	}
	ws := ev.workspaceOf(dir)
	name, err := filepath.Rel(ws, dir)
	if err != nil {
		return nil
	}
	if name == "." {
		name = ""
	}
	p := &bazelPackage{workspace: ws, dir: dir, name: filepath.ToSlash(name), targets: map[string]*bazelTarget{}}
	ev.packages[dir] = p
	thread := ev.thread(file)
	thread.SetLocal(bazelPackageKey, p)
	if _, err := ev.run(thread, file, src, ws); err != nil {
		// What the file declared before failing is still recorded.
		ev.d.debugf("Could not fully evaluate the Bazel file %s: %v", file, err)
	}
	return p
}

const bazelPackageKey = "bazel-package"

func (ev *bazelEval) thread(file string) *starlark.Thread {
	thread := &starlark.Thread{
		Name:  file,
		Print: func(*starlark.Thread, string) {},
		Load:  ev.load,
	}
	thread.SetMaxExecutionSteps(maxBazelSteps)
	return thread
}

// run executes a file on thread, canceled past maxBazelFileTime: the step
// limit does not count the time builtins take. Past maxBazelFiles, no file
// is run.
func (ev *bazelEval) run(thread *starlark.Thread, file string, src []byte, ws string) (starlark.StringDict, error) {
	if ev.evaluated >= maxBazelFiles {
		return nil, fmt.Errorf("more than %d Bazel files evaluated", maxBazelFiles)
	}
	ev.evaluated++
	timer := time.AfterFunc(maxBazelFileTime, func() { thread.Cancel("evaluation took too long") })
	defer timer.Stop()
	return ev.exec(thread, file, src, ws)
}

// exec runs a BUILD or .bzl file. Every name it uses that neither Starlark,
// Bazel nor the file itself defines is a recording stand-in.
func (ev *bazelEval) exec(thread *starlark.Thread, file string, src []byte, ws string) (starlark.StringDict, error) {
	f, err := bazelFileOptions.Parse(file, src, 0)
	if err != nil {
		return nil, err
	}
	predeclared := ev.builtins(file)
	loads := map[string][]string{}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Ident:
			if !starlark.Universe.Has(x.Name) && !predeclared.Has(x.Name) {
				predeclared[x.Name] = newStub(x.Name)
			}
		case *syntax.LoadStmt:
			for _, from := range x.From {
				loads[x.Module.Value.(string)] = append(loads[x.Module.Value.(string)], from.Name)
			}
		}
		return true
	})
	thread.SetLocal(bazelLoadsKey, loads)
	thread.SetLocal(bazelFileKey, file)
	thread.SetLocal(bazelWorkspaceKey, ws)
	prog, err := starlark.FileProgram(f, predeclared.Has)
	if err != nil {
		return nil, err
	}
	globals, err := prog.Init(thread, predeclared)
	nameRules(globals)
	return globals, err
}

const (
	bazelLoadsKey     = "bazel-loads"
	bazelFileKey      = "bazel-file"
	bazelWorkspaceKey = "bazel-workspace"
)

// nameRules gives the rules and macros a .bzl file creates the name they are
// exported under, the kind of the targets they declare.
func nameRules(globals starlark.StringDict) {
	for name, v := range globals {
		if s, ok := v.(*stub); ok && s.made {
			s.name = name
		}
	}
}

// load evaluates a .bzl file of the repository, or returns stand-ins for the
// symbols a file loads from an external repository.
func (ev *bazelEval) load(thread *starlark.Thread, module string) (starlark.StringDict, error) {
	ws, _ := thread.Local(bazelWorkspaceKey).(string)
	file, _ := thread.Local(bazelFileKey).(string)
	loads, _ := thread.Local(bazelLoadsKey).(map[string][]string)
	stubs := func() starlark.StringDict {
		out := starlark.StringDict{}
		for _, name := range loads[module] {
			out[name] = newStub(name)
		}
		return out
	}
	bzl, ok := ev.labelPath(module, ws, filepath.Dir(file))
	if !ok {
		return stubs(), nil
	}
	// One module whatever links lead to it, so that a cycle is one.
	bzl = ev.d.idx.canonical(bzl)
	if m, ok := ev.modules[bzl]; ok {
		if m == nil {
			return nil, fmt.Errorf("cycle loading %s", module)
		}
		return withStubs(m.globals, stubs()), nil
	}
	src := ev.d.read(bzl)
	if src == nil {
		return stubs(), nil
	}
	ev.modules[bzl] = nil
	// A .bzl file declares no target itself: only the macros it defines do,
	// in the package calling them.
	child := ev.thread(bzl)
	child.SetLocal(bazelPackageKey, (*bazelPackage)(nil))
	globals, err := ev.run(child, bzl, src, ev.workspaceOf(filepath.Dir(bzl)))
	if err != nil {
		ev.d.debugf("Could not fully evaluate the Bazel file %s: %v", bzl, err)
	}
	ev.modules[bzl] = &bazelModule{globals: globals, err: err}
	return withStubs(globals, stubs()), nil
}

// withStubs is globals, with the stand-ins of the names a failed evaluation
// left undefined.
func withStubs(globals, stubs starlark.StringDict) starlark.StringDict {
	out := starlark.StringDict{}
	for k, v := range stubs {
		out[k] = v
	}
	for k, v := range globals {
		out[k] = v
	}
	return out
}

// labelPath returns the file a label of this workspace names, from the
// package at dir.
func (ev *bazelEval) labelPath(label, ws, dir string) (string, bool) {
	pkgPath, name, ok := ev.splitLabel(label, ws, dir)
	if !ok {
		return "", false
	}
	return filepath.Join(pkgPath, filepath.FromSlash(name)), true
}

// splitLabel returns the package directory and the name a label names, from
// the package at dir. A label of an external repository names nothing here.
func (ev *bazelEval) splitLabel(label, ws, dir string) (pkgDir, name string, ok bool) {
	label = strings.TrimPrefix(label, "@@")
	if strings.HasPrefix(label, "@") {
		repo, rest, found := strings.Cut(label[1:], "//")
		if !found || repo != "" {
			return "", "", false
		}
		label = "//" + rest
	}
	switch {
	case strings.HasPrefix(label, "//"):
		pkg, target, hasName := strings.Cut(label[2:], ":")
		if !hasName {
			target = path.Base(pkg)
		}
		return filepath.Join(ws, filepath.FromSlash(pkg)), target, true
	case strings.HasPrefix(label, ":"):
		return dir, label[1:], true
	case strings.Contains(label, "://"):
		return "", "", false
	default:
		return dir, label, true
	}
}

// args are the arguments of a call of a builtin.
type (
	args   = starlark.Tuple
	kwargs = []starlark.Tuple
)

// builtins are what Bazel predeclares for a BUILD or .bzl file.
func (ev *bazelEval) builtins(file string) starlark.StringDict {
	glob := starlark.NewBuiltin("glob", ev.glob)
	packageName := starlark.NewBuiltin("package_name", builtinPackageName)
	repositoryName := starlark.NewBuiltin("repository_name", constant(starlark.String("@")))
	none := func(name string) *starlark.Builtin { return starlark.NewBuiltin(name, constant(starlark.None)) }
	fail := starlark.NewBuiltin("fail", func(_ *starlark.Thread, _ *starlark.Builtin, a args, _ kwargs) (starlark.Value, error) {
		// A macro checking its arguments against what stands for a value of an
		// external repository must not cost the package its other targets.
		ev.d.debugf("Bazel file %s called fail%v", file, a)
		return starlark.None, nil
	})
	native := starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"glob": glob, "package_name": packageName, "repository_name": repositoryName,
		"existing_rules": starlark.NewBuiltin("existing_rules", constant(starlark.NewDict(0))),
		"existing_rule":  none("existing_rule"),
		"package":        none("package"),
		"exports_files":  none("exports_files"),
	})
	return starlark.StringDict{
		"glob": glob, "package_name": packageName, "repository_name": repositoryName,
		"select": starlark.NewBuiltin("select", builtinSelect), "Label": starlark.NewBuiltin("Label", builtinLabel),
		"depset": starlark.NewBuiltin("depset", builtinDepset), "fail": fail,
		"struct": starlark.NewBuiltin("struct", starlarkstruct.Make),
		"json":   json.Module, "native": native,
		"package": none("package"), "licenses": none("licenses"), "exports_files": none("exports_files"),
		"workspace": none("workspace"), "module": none("module"),
	}
}

// constant is a builtin returning v.
func constant(v starlark.Value) func(*starlark.Thread, *starlark.Builtin, args, kwargs) (starlark.Value, error) {
	return func(*starlark.Thread, *starlark.Builtin, args, kwargs) (starlark.Value, error) {
		return v, nil
	}
}

// builtinPackageName is package_name(): the path of the calling package.
func builtinPackageName(thread *starlark.Thread, _ *starlark.Builtin, _ args, _ kwargs) (starlark.Value, error) {
	if p, ok := thread.Local(bazelPackageKey).(*bazelPackage); ok && p != nil {
		return starlark.String(p.name), nil
	}
	return starlark.String(""), nil
}

// builtinSelect is select(): the default branch, or else the first one.
func builtinSelect(_ *starlark.Thread, _ *starlark.Builtin, a args, _ kwargs) (starlark.Value, error) {
	if len(a) == 0 {
		return starlark.None, nil
	}
	d, ok := a[0].(*starlark.Dict)
	if !ok {
		return a[0], nil
	}
	if v, found, _ := d.Get(starlark.String("//conditions:default")); found {
		return v, nil
	}
	if items := d.Items(); len(items) > 0 {
		return items[0][1], nil
	}
	return starlark.None, nil
}

// builtinLabel is Label(): the label as written.
func builtinLabel(_ *starlark.Thread, _ *starlark.Builtin, a args, _ kwargs) (starlark.Value, error) {
	if len(a) == 0 {
		return starlark.String(""), nil
	}
	return a[0], nil
}

// builtinDepset is depset(): a list of its items, direct ones included.
func builtinDepset(_ *starlark.Thread, _ *starlark.Builtin, a args, kw kwargs) (starlark.Value, error) {
	var items []starlark.Value
	for _, v := range a {
		items = append(items, valuesOf(v)...)
	}
	for _, kv := range kw {
		if k, _ := starlark.AsString(kv[0]); k == "direct" {
			items = append(items, valuesOf(kv[1])...)
		}
	}
	return starlark.NewList(items), nil
}

// valuesOf returns the items of an iterable value.
func valuesOf(v starlark.Value) []starlark.Value {
	it, ok := v.(starlark.Iterable)
	if !ok {
		return nil
	}
	iter := it.Iterate()
	defer iter.Done()
	var out []starlark.Value
	var x starlark.Value
	for iter.Next(&x) {
		out = append(out, x)
	}
	return out
}

// glob lists the files of the calling package matching the include patterns
// and none of the exclude ones, not descending into subpackages, as Bazel does.
func (ev *bazelEval) glob(thread *starlark.Thread, _ *starlark.Builtin, a args, kw kwargs) (starlark.Value, error) {
	p, _ := thread.Local(bazelPackageKey).(*bazelPackage)
	if p == nil {
		return starlark.NewList(nil), nil
	}
	var include, exclude []string
	if len(a) > 0 {
		include = stringsOf(a[0])
	}
	if len(a) > 1 {
		exclude = stringsOf(a[1])
	}
	for _, kv := range kw {
		switch k, _ := starlark.AsString(kv[0]); k {
		case "include":
			include = stringsOf(kv[1])
		case "exclude":
			exclude = stringsOf(kv[1])
		}
	}
	includes, excludes := globRegexps(include), globRegexps(exclude)
	var out []starlark.Value
	for _, f := range ev.packageFiles(p.dir) {
		if matchesAny(includes, f) && !matchesAny(excludes, f) {
			out = append(out, starlark.String(f))
		}
	}
	return starlark.NewList(out), nil
}

// globRegexps compiles the glob patterns.
func globRegexps(patterns []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range patterns {
		if re := globRegexp(p); re != nil {
			out = append(out, re)
		}
	}
	return out
}

func matchesAny(res []*regexp.Regexp, name string) bool {
	for _, re := range res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// packageFiles lists the files of the package at dir, relative to it, without
// those of its subpackages.
func (ev *bazelEval) packageFiles(dir string) []string {
	if files, ok := ev.listings[dir]; ok {
		return files
	}
	var out []string
	var walk func(abs, rel string)
	walk = func(abs, rel string) {
		for _, e := range readDir(ev.d.fsys(), abs) {
			childRel := e.Name()
			if rel != "" {
				childRel = rel + "/" + e.Name()
			}
			child := filepath.Join(abs, e.Name())
			if e.IsDir() {
				if _, sub := ev.buildFile(child); !sub {
					walk(child, childRel)
				}
				continue
			}
			out = append(out, childRel)
		}
	}
	walk(dir, "")
	sort.Strings(out)
	ev.listings[dir] = out
	return out
}

func stringsOf(v starlark.Value) []string {
	var out []string
	for _, x := range valuesOf(v) {
		if s, ok := starlark.AsString(x); ok {
			out = append(out, s)
		}
	}
	return out
}

// stub stands for a rule, macro or value Bazel files use that the scan does
// not define: called with a name, it records a target; read, it is a
// placeholder.
type stub struct {
	name string
	// made is set for a rule or macro a .bzl file creates, as with rule(),
	// named after the global it is exported as.
	made bool
}

var (
	_ starlark.Callable  = (*stub)(nil)
	_ starlark.HasAttrs  = (*stub)(nil)
	_ starlark.Iterable  = (*stub)(nil)
	_ starlark.Indexable = (*stub)(nil)
	_ starlark.Mapping   = (*stub)(nil)
	_ starlark.HasBinary = (*stub)(nil)
)

func newStub(name string) *stub { return &stub{name: name} }

func (s *stub) String() string        { return "<" + s.name + ">" }
func (s *stub) Type() string          { return "stub" }
func (s *stub) Freeze()               {}
func (s *stub) Truth() starlark.Bool  { return starlark.False }
func (s *stub) Hash() (uint32, error) { return starlark.String(s.name).Hash() }
func (s *stub) Name() string          { return s.name }
func (s *stub) Attr(name string) (starlark.Value, error) {
	return newStub(s.name + "." + name), nil
}
func (s *stub) AttrNames() []string        { return nil }
func (s *stub) Iterate() starlark.Iterator { return emptyIterator{} }
func (s *stub) Len() int                   { return 0 }
func (s *stub) Index(int) starlark.Value   { return newStub(s.name + "[]") }
func (s *stub) Get(starlark.Value) (starlark.Value, bool, error) {
	return newStub(s.name + "[]"), true, nil
}
func (s *stub) Binary(syntax.Token, starlark.Value, starlark.Side) (starlark.Value, error) {
	return s, nil
}

func (s *stub) CallInternal(thread *starlark.Thread, _ args, kw kwargs) (starlark.Value, error) {
	attrs := map[string]interface{}{}
	for _, kv := range kw {
		if k, ok := starlark.AsString(kv[0]); ok {
			attrs[k] = toGo(kv[1])
		}
	}
	if name, ok := attrs["name"].(string); ok && name != "" {
		if p, ok := thread.Local(bazelPackageKey).(*bazelPackage); ok && p != nil {
			t := &bazelTarget{kind: s.name, name: name, attrs: attrs, pkg: p}
			if _, dup := p.targets[name]; !dup {
				p.order = append(p.order, t)
			}
			p.targets[name] = t
		}
	}
	// rule(), macro() and the like make a rule.
	return &stub{name: s.name + "()", made: true}, nil
}

type emptyIterator struct{}

func (emptyIterator) Next(*starlark.Value) bool { return false } //nolint:gocritic // starlark.Iterator's method
func (emptyIterator) Done()                     {}

// toGo converts a Starlark value to the Go values of decoded YAML.
func toGo(v starlark.Value) interface{} {
	switch x := v.(type) {
	case starlark.NoneType:
		return nil
	case starlark.Bool:
		return bool(x)
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return i
		}
		return x.String()
	case starlark.Float:
		return float64(x)
	case starlark.String:
		return string(x)
	case *starlark.List, starlark.Tuple:
		var out []interface{}
		for _, e := range valuesOf(v) {
			out = append(out, toGo(e))
		}
		return out
	case *starlark.Dict:
		out := map[string]interface{}{}
		for _, item := range x.Items() {
			k, ok := starlark.AsString(item[0])
			if !ok {
				k = item[0].String()
			}
			out[k] = toGo(item[1])
		}
		return out
	case *starlarkstruct.Struct:
		out := map[string]interface{}{}
		for _, name := range x.AttrNames() {
			if a, err := x.Attr(name); err == nil {
				out[name] = toGo(a)
			}
		}
		return out
	}
	return v.String()
}

// target returns the target a label names from pkg, nil for a file or a
// label of another repository.
func (ev *bazelEval) target(label string, from *bazelPackage) (t *bazelTarget, file string) {
	dir, name, ok := ev.splitLabel(label, from.workspace, from.dir)
	if !ok {
		return nil, ""
	}
	if dir == from.dir && strings.Contains(name, "/") {
		// A path in the package, not a target.
		return nil, filepath.Join(dir, filepath.FromSlash(name))
	}
	if p := ev.pkg(dir); p != nil {
		if t, ok := p.targets[name]; ok {
			return t, ""
		}
	}
	return nil, filepath.Join(dir, filepath.FromSlash(name))
}

// fileAttrs are the attributes listing a target's files.
var fileAttrs = []string{"srcs", "files", "data", "chart", "chart_yaml", "values", "value_files", "values_files"}

// files returns the files a label stands for: a file, or those a target lists.
func (ev *bazelEval) files(label string, from *bazelPackage, depth int) []string {
	key := fileKey{pkg: from, label: label}
	if out, ok := ev.fileMemo[key]; ok {
		// Known, or being followed: a cycle leads nowhere new.
		return out
	}
	t, file := ev.target(label, from)
	if t == nil {
		var out []string
		if file != "" && fileExists(ev.d.fsys(), file) {
			out = []string{file}
		}
		ev.fileMemo[key] = out
		return out
	}
	if depth >= maxLabelDepth {
		return nil
	}
	ev.fileMemo[key] = nil
	seen := map[string]bool{}
	var out []string
	for _, attr := range append(fileAttrs, "actual") {
		for _, l := range labelsOf(t.attrs[attr]) {
			for _, f := range ev.files(l, t.pkg, depth+1) {
				if !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
	}
	ev.fileMemo[key] = out
	return out
}

func labelsOf(v interface{}) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]interface{}:
		// A dict of labels to something, as images do.
		return nil
	}
	return nil
}

// chartDirOf returns the chart of the scan a target is, or packages through
// the attributes leading to a chart.
func (ev *bazelEval) chartDirOf(t *bazelTarget, depth int) (string, bool) {
	if res, ok := ev.chartMemo[t]; ok {
		return res.dir, res.ok
	}
	if depth >= maxLabelDepth {
		return "", false
	}
	// Being followed: a cycle leads to no chart.
	ev.chartMemo[t] = chartResult{}
	dir, ok := ev.followChart(t, depth)
	ev.chartMemo[t] = chartResult{dir: dir, ok: ok}
	return dir, ok
}

// followChart is chartDirOf, unmemoized.
func (ev *bazelEval) followChart(t *bazelTarget, depth int) (string, bool) {
	// Its own files, through file groups.
	for _, attr := range []string{"srcs", "files", "data", "chart_yaml", "chart"} {
		for _, l := range labelsOf(t.attrs[attr]) {
			for _, f := range ev.files(l, t.pkg, depth) {
				if filepath.Base(f) == chartFileName {
					if dir, ok := ev.d.idx.chartDir(filepath.Dir(f)); ok {
						return dir, true
					}
				}
			}
		}
	}
	// The chart of what it packages or stands for.
	for _, attr := range []string{"chart", "bundle", "actual", "src", "target"} {
		for _, l := range labelsOf(t.attrs[attr]) {
			next, _ := ev.target(l, t.pkg)
			if next == nil || next == t {
				continue
			}
			if dir, ok := ev.chartDirOf(next, depth+1); ok {
				return dir, true
			}
		}
	}
	return "", false
}

// installationKind matches the rules installing a chart.
var installationKind = regexp.MustCompile(`(?i)install|release|deploy`)

// installation records the installation t declares, when it is one.
func (ev *bazelEval) installation(t *bazelTarget) {
	chartRelease := str(t.attrs, "release_name") != "" || str(t.attrs, "install_name") != ""
	if !installationKind.MatchString(t.kind) && !chartRelease {
		return
	}
	chartDir, ok := ev.chartDirOf(t, 0)
	if !ok {
		return
	}
	release, namespace, cnab := installationNames(t)
	inst := Installation{
		Release:   release,
		Namespace: namespace,
		Source:    fmt.Sprintf("Bazel target //%s:%s (%s)", t.pkg.name, t.name, t.kind),
		Origin:    OriginDescriptor,
	}
	var files []string
	for _, attr := range []string{"value_files", "values_files", "values_file", "values"} {
		for _, l := range labelsOf(t.attrs[attr]) {
			files = append(files, ev.valueFiles(l, t.pkg, chartDir)...)
		}
	}
	// CNAB tools apply the environment files unless values files replace
	// them.
	if strategy := str(asMap(t.attrs["parameters"]), "valuesStrategies"); cnab && (len(files) == 0 || strategy == valuesStrategyMerge) {
		files = append(environmentFiles(ev.d.fsys(), chartDir, t.name), files...)
	}
	for _, f := range files {
		inst.Layers = append(inst.Layers, Layer{File: f})
	}
	if values, ok := helmValues(t.attrs["values"]); ok {
		inst.Layers = append(inst.Layers, Layer{Values: values})
	}
	ev.d.idx.add(chartDir, &inst)
}

// installationNames returns the release name and namespace an installation
// target gives, and whether its name is a CNAB installation name.
func installationNames(t *bazelTarget) (release, namespace string, cnab bool) {
	release = firstNonEmpty(str(t.attrs, "release_name"), str(t.attrs, "install_name"), str(t.attrs, "installation_name"))
	namespace = str(t.attrs, "namespace")
	parsed, cnab := parseCNABInstallationName(t.name)
	if !cnab {
		return firstNonEmpty(release, t.name), namespace, false
	}
	return firstNonEmpty(release, parsed.release), firstNonEmpty(namespace, parsed.namespace), true
}

// valueFiles resolves an entry of a value_files attribute: a path of the
// chart, as CNAB tools read it from the bundle, or a label of the files to
// merge.
func (ev *bazelEval) valueFiles(label string, from *bazelPackage, chartDir string) []string {
	if !strings.HasPrefix(label, ":") && !strings.HasPrefix(label, "//") && !strings.HasPrefix(label, "@") {
		if p := filepath.Join(chartDir, filepath.FromSlash(label)); fileExists(ev.d.fsys(), p) {
			return []string{p}
		}
	}
	var out []string
	for _, f := range ev.files(label, from, 0) {
		if isYAMLFile(f) || strings.HasSuffix(f, ".json") {
			out = append(out, f)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// cnabInstallationName is an installation name of Datadog CNAB tools,
// <release>.<namespace>.<cluster>.<datacenter>.
type cnabInstallationName struct {
	release, namespace, cluster, datacenter string
}

// parseCNABInstallationName splits an installation name of Datadog CNAB tools.
func parseCNABInstallationName(name string) (cnabInstallationName, bool) {
	parts := strings.SplitN(name, ".", 4)
	if len(parts) < 4 || parts[0] == "" || parts[1] == "" {
		return cnabInstallationName{}, false
	}
	return cnabInstallationName{release: parts[0], namespace: parts[1], cluster: parts[2], datacenter: parts[3]}, true
}

// environmentFiles returns the values/environments files of the chart at dir
// whose name, "_" standing for any characters, matches the installation
// name, the least specific first, as Datadog CNAB tools apply them.
func environmentFiles(fsys vfs.FS, chartDir, installation string) []string {
	var matched []string
	for _, rel := range walkFiles(fsys, filepath.Join(chartDir, "values", "environments")) {
		if strings.Contains(rel, "/") || !isYAMLFile(rel) {
			continue
		}
		if environmentPattern(environmentFileName(rel)).MatchString(installation) {
			matched = append(matched, rel)
		}
	}
	sortBySpecificity(matched)
	out := make([]string, len(matched))
	for i, rel := range matched {
		out[i] = filepath.Join(chartDir, "values", "environments", rel)
	}
	return out
}

// bundleChart returns the chart the target name of the package at dir leads
// to, as a deploy.yaml app's depName names a bundle.
func (ev *bazelEval) bundleChart(dir, name string) (string, bool) {
	p := ev.pkg(dir)
	if p == nil {
		return "", false
	}
	t, ok := p.targets[name]
	if !ok {
		return "", false
	}
	return ev.chartDirOf(t, 0)
}

// dependencyCharts returns the charts of the bundles named name that the
// bundles of the package at dir depend on.
func (ev *bazelEval) dependencyCharts(dir, name string) []string {
	p := ev.pkg(dir)
	if p == nil {
		return nil
	}
	var out []string
	for _, t := range p.order {
		for _, l := range labelsOf(t.attrs["bundle_dependencies"]) {
			dep, _ := ev.target(l, p)
			if dep == nil || dep.name != name {
				continue
			}
			if c, ok := ev.chartDirOf(dep, 0); ok {
				out = append(out, c)
			}
		}
	}
	return uniqueStrings(out)
}

// packageCharts returns the charts the bundles of the package at dir lead to,
// only those it defines itself when own is set, not those an alias names.
func (ev *bazelEval) packageCharts(dir string, own bool) []string {
	p := ev.pkg(dir)
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range p.order {
		if installationKind.MatchString(t.kind) || own && t.kind == "alias" {
			continue
		}
		if c, ok := ev.chartDirOf(t, 0); ok && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
