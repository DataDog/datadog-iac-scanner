/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"net/url"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

const (
	moduleDependencyDirect     = "direct"
	moduleDependencyTransitive = "transitive"
	moduleSourceTypeGit        = "git"
	moduleSourceTypeLocal      = "local"
	moduleSourceTypeRegistry   = "registry"
	moduleSourceSchemeFile     = "file"
	parentDirectoryPath        = ".."
)

// RemoteModuleProvenance holds resolved identity for a remote module call site.
type RemoteModuleProvenance struct {
	Source          string
	ResolvedVersion string
	ResolvedRef     string
	CanonicalSource string
	SourceType      string
	ModuleRoot      string
	PackageRoot     string
}

type moduleProvenanceLookup func(callerRoot, source, version, moduleName string) (RemoteModuleProvenance, bool)

// maxCachedChainDepth bounds the call chains attribution is memoized for;
// deeper chains are rare and are attributed without the cache.
const maxCachedChainDepth = 8

// moduleAttributionCache memoizes attribution within one root evaluation.
// Attribution depends only on the HCL blocks involved: a resource block's
// count/for_each instances and every resource reached through the same module
// blocks share their work. Keys are HCL nodes, so a cache must not outlive
// the root whose parse it holds.
type moduleAttributionCache struct {
	resources  map[resourceCacheKey]*model.ModuleAttribution
	chains     map[chainCacheKey]modulePathEntry
	attributes map[*hclsyntax.Body][]attributeVariables
	arguments  map[*hclsyntax.Attribute][]string
	locals     map[hclsyntax.Expression][]string
}

type chainCacheKey struct {
	calls [maxCachedChainDepth]*hclsyntax.Body
	depth int
}

type resourceCacheKey struct {
	resource *hclsyntax.Body
	chain    chainCacheKey
}

type modulePathEntry struct {
	path []model.ModulePathHop
	// packages holds, per hop, the remote package the call resolved to, or the
	// zero value for calls that stay in their caller's package.
	packages []modulePackage
}

// modulePackage is the remote package a module call resolves into: address
// names the directory root, which file names inside the package are relative
// to.
type modulePackage struct {
	root       string
	address    string
	sourceType string
	version    string
}

func newModuleAttributionCache() *moduleAttributionCache {
	return &moduleAttributionCache{
		resources:  make(map[resourceCacheKey]*model.ModuleAttribution),
		chains:     make(map[chainCacheKey]modulePathEntry),
		attributes: make(map[*hclsyntax.Body][]attributeVariables),
		arguments:  make(map[*hclsyntax.Attribute][]string),
		locals:     make(map[hclsyntax.Expression][]string),
	}
}

func chainKey(chain []tfeval.CallSite) (chainCacheKey, bool) {
	var key chainCacheKey
	if len(chain) == 0 || len(chain) > maxCachedChainDepth {
		return key, false
	}
	for i := range chain {
		if chain[i].Body == nil {
			return key, false
		}
		key.calls[i] = chain[i].Body
	}
	key.depth = len(chain)
	return key, true
}

// attribution returns the resource's attribution, shared with every resource
// of the same block reached through the same module blocks. Shared
// attributions are read-only; callers clone before narrowing one.
func (c *moduleAttributionCache) attribution(
	r *tfeval.ResolvedResource, repoPath string, lookup moduleProvenanceLookup,
) *model.ModuleAttribution {
	chain, ok := chainKey(r.CallChain)
	if !ok || r.Body == nil {
		return buildModuleAttribution(r, repoPath, lookup, c)
	}
	key := resourceCacheKey{resource: r.Body, chain: chain}
	if attr, ok := c.resources[key]; ok {
		return attr
	}
	attr := buildModuleAttribution(r, repoPath, lookup, c)
	c.resources[key] = attr
	return attr
}

func (c *moduleAttributionCache) modulePath(
	chain []tfeval.CallSite, repoPath string, lookup moduleProvenanceLookup,
) modulePathEntry {
	key, ok := chainKey(chain)
	if c == nil || !ok {
		return buildModulePath(chain, repoPath, lookup)
	}
	if entry, ok := c.chains[key]; ok {
		return entry
	}
	entry := buildModulePath(chain, repoPath, lookup)
	c.chains[key] = entry
	return entry
}

func buildModuleAttribution(
	r *tfeval.ResolvedResource,
	repoPath string,
	lookup moduleProvenanceLookup,
	cache *moduleAttributionCache,
) *model.ModuleAttribution {
	if r == nil || len(r.CallChain) == 0 {
		return nil
	}

	entry := cache.modulePath(r.CallChain, repoPath, lookup)
	path := entry.path
	if len(path) == 0 {
		return nil
	}

	leaf := path[len(path)-1]
	dependencyType := moduleDependencyDirect
	if len(path) > 1 {
		dependencyType = moduleDependencyTransitive
	}

	bodyPath := absPath(r.DefinedIn, repoPath)
	bodyFile, pkg := moduleFileName(bodyPath, repoPath, entry.packages)
	bodyEnd := r.DefEndLine
	if bodyEnd < r.DefLine {
		bodyEnd = r.DefLine
	}

	attr := &model.ModuleAttribution{
		SourceType:     moduleSourceTypeLocal,
		DependencyType: dependencyType,
		CallSite:       rootCallAnchor(&r.CallChain[0], path[0].CodeLocation),
		ModuleCodeLocation: model.SourceLocation{
			Filename:    bodyFile,
			LineStart:   r.DefLine,
			LineEnd:     bodyEnd,
			ColumnStart: r.DefColumn,
			ColumnEnd:   r.DefEndColumn,
		},
		ModulePath:      path,
		ModuleCodeOwned: leaf.SourceType == moduleSourceTypeLocal && pathWithinRoot(filepath.Dir(bodyPath), repoPath),
		Arguments:       cache.resourceArguments(r, path[0].CodeLocation.Filename),
	}
	if pkg.root != "" {
		attr.Source, attr.SourceType, attr.Version = pkg.address, pkg.sourceType, pkg.version
	}
	return attr
}

// rootCallAnchor is where a finding not set by a call argument points: the
// root call's source argument, which names the module to change or upgrade.
func rootCallAnchor(site *tfeval.CallSite, block model.SourceLocation) model.SourceLocation {
	if site.Body == nil {
		return block
	}
	source, ok := site.Body.Attributes[moduleSourceArg]
	if !ok {
		return block
	}
	return attributeLocation(source, block.Filename)
}

// buildModulePath returns one hop per call in chain, along with the package
// each call resolved to. A local call inside a remote package is reported as
// that package's subdirectory.
func buildModulePath(
	chain []tfeval.CallSite,
	repoPath string,
	lookup moduleProvenanceLookup,
) modulePathEntry {
	entry := modulePathEntry{
		path:     make([]model.ModulePathHop, 0, len(chain)),
		packages: make([]modulePackage, 0, len(chain)),
	}
	var pkg modulePackage
	for i := range chain {
		site := &chain[i]
		location := declarationLocation(
			site.CalledFrom,
			site.CalledLine,
			site.CalledEndLine,
			site.CalledColumn,
			site.CalledEndColumn,
			repoPath,
		)
		if i > 0 {
			location.Filename, _ = moduleFileName(site.CalledFrom, repoPath, entry.packages)
		}
		hop := model.ModulePathHop{
			Name:         site.ModuleName,
			CodeLocation: location,
		}
		callerRoot := moduleCallerRoot(site.CalledFrom, repoPath)
		root, address := enrichModuleHop(&hop, callerRoot, repoPath, site, lookup)
		var called modulePackage
		switch {
		case hop.SourceType != moduleSourceTypeLocal:
			pkg = modulePackage{
				root:       root,
				address:    address,
				sourceType: hop.SourceType,
				version:    hop.Version,
			}
			called = pkg
		case pkg.root != "":
			pkg.describe(&hop, site.Source, callerRoot)
		}
		entry.path = append(entry.path, hop)
		entry.packages = append(entry.packages, called)
	}
	return entry
}

// describe reports a local call resolving inside the package as the package's
// subdirectory. Calls leaving the package keep their local identity.
func (p *modulePackage) describe(hop *model.ModulePathHop, source, callerRoot string) {
	dir := absPath(strings.TrimPrefix(source, "git::"), callerRoot)
	if !pathWithinRoot(dir, p.root) {
		return
	}
	rel, err := filepath.Rel(filepath.Clean(p.root), dir)
	if err != nil {
		return
	}
	hop.Source = joinModuleSubdir(p.address, filepath.ToSlash(rel))
	hop.SourceType = p.sourceType
	hop.Version = p.version
}

// modulePackageAddress strips the "//subdir" of a module source, leaving the
// address of the package holding it.
func modulePackageAddress(source string) string {
	address, _ := splitModuleSubdir(source)
	return address
}

func splitModuleSubdir(source string) (address, subdir string) {
	start := 0
	if i := strings.Index(source, "://"); i >= 0 {
		start = i + len("://")
	}
	if i := strings.Index(source[start:], "//"); i >= 0 {
		return source[:start+i], source[start+i+len("//"):]
	}
	return source, ""
}

// joinModuleSubdir appends rel to the subdirectory of a module address.
func joinModuleSubdir(address, rel string) string {
	if rel == "." || rel == "" {
		return address
	}
	if _, subdir := splitModuleSubdir(address); subdir != "" {
		return address + "/" + rel
	}
	return address + "//" + rel
}

// enrichModuleHop fills the hop's source identity and returns the root of a
// resolved remote module with the address naming it, or empty values when the
// call has no resolved package. A git module's version is the ref its source
// declares, falling back to the resolved commit when it declares none.
func enrichModuleHop(
	hop *model.ModulePathHop,
	callerRoot string,
	repoPath string,
	site *tfeval.CallSite,
	lookup moduleProvenanceLookup,
) (root, address string) {
	sourceType, _ := tfmodules.DetectModuleSourceType(site.Source)
	hop.SourceType = sourceType
	hop.Source = normalizedModuleSource(site.Source, sourceType, callerRoot, repoPath)
	declaredRef := declaredGitRef(site.Source)
	if sourceType == moduleSourceTypeGit {
		hop.Version = declaredRef
	}

	if lookup != nil {
		if prov, ok := lookup(callerRoot, site.Source, site.Version, site.ModuleName); ok {
			if prov.SourceType != "" {
				hop.SourceType = prov.SourceType
			}
			source := firstNonEmpty(prov.CanonicalSource, prov.Source, site.Source)
			hop.Source = normalizedModuleSource(source, hop.SourceType, callerRoot, repoPath)
			switch hop.SourceType {
			case moduleSourceTypeRegistry:
				hop.Version = strings.TrimSpace(prov.ResolvedVersion)
			case moduleSourceTypeGit:
				hop.Version = firstNonEmpty(declaredRef, prov.ResolvedRef)
			}
			if hop.SourceType == moduleSourceTypeLocal {
				return "", ""
			}
			return moduleRootAddress(&prov, hop.Source)
		}
	}
	return "", ""
}

// moduleRootAddress returns the directory module files are named from and the
// address naming it: the package root and the source without its subdirectory
// when the source addresses a subdirectory of that package, the module root and
// the full source otherwise.
func moduleRootAddress(prov *RemoteModuleProvenance, source string) (root, address string) {
	pkgAddress := modulePackageAddress(source)
	if prov.ModuleRoot == "" ||
		(prov.PackageRoot != "" && pkgAddress != source && filepath.Clean(prov.PackageRoot) != filepath.Clean(prov.ModuleRoot)) {
		return prov.PackageRoot, pkgAddress
	}
	return prov.ModuleRoot, source
}

// declaredGitRef returns the ref query parameter of a git module source.
func declaredGitRef(source string) string {
	_, query, ok := strings.Cut(source, "?")
	if !ok {
		return ""
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(values.Get("ref"))
}

// normalizedModuleSource returns the reported identity of a module source.
// Remote sources are lowercased so spellings differing only in case group as
// one module; local sources keep their casing since they name repository paths.
func normalizedModuleSource(source, sourceType, callerRoot, repoPath string) string {
	source = strings.TrimSpace(source)
	if sourceType == moduleSourceTypeRegistry {
		source = strings.SplitN(source, "@", 2)[0]
		if addr, err := tfmodules.ParseRegistryModuleSource(source); err == nil {
			return strings.ToLower(addr.String())
		}
	}
	if sourceType == moduleSourceTypeLocal {
		localSource := strings.TrimPrefix(source, "git::")
		if parsed, err := url.Parse(localSource); err == nil && parsed.Scheme == moduleSourceSchemeFile {
			localSource = fileURLPath(parsed.Path)
		}
		if portablePathIsAbs(localSource) && !filepath.IsAbs(localSource) {
			return portablePathBase(localSource)
		}
		target := absPath(localSource, callerRoot)
		// No repo root in content-push mode: keep the pushed shape rather than
		// collapsing to a basename (same convention as repoRelativeFile).
		if repoPath == "" {
			return filepath.ToSlash(filepath.Clean(target))
		}
		if pathWithinRoot(target, repoPath) {
			rel, _ := filepath.Rel(filepath.Clean(repoPath), target)
			return filepath.ToSlash(rel)
		}
		return filepath.Base(filepath.Clean(target))
	}
	return lowerRemoteSource(normalizedRemoteModuleSource(source))
}

// lowerRemoteSource lowercases the parts of a remote source that are case
// insensitive: the host always, the owner and repository only on hosts known
// to ignore their case. The subdirectory is a real path and keeps its casing.
func lowerRemoteSource(source string) string {
	scheme, rest, hasScheme := strings.Cut(source, "://")
	if !hasScheme {
		return source
	}
	pkg, subdir, hasSubdir := strings.Cut(rest, "//")
	host, repo, _ := strings.Cut(pkg, "/")
	host = strings.ToLower(host)
	if host == "github.com" || host == "bitbucket.org" {
		repo = strings.ToLower(repo)
	}
	out := scheme + "://" + host
	if repo != "" {
		out += "/" + repo
	}
	if hasSubdir {
		out += "//" + subdir
	}
	return out
}

func normalizedRemoteModuleSource(source string) string {
	source = strings.TrimPrefix(source, "git::")
	source = strings.SplitN(source, "?", 2)[0]
	if address, ok := httpsGitAddress(source); ok {
		source = address
	} else if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" {
		if parsed.Scheme == moduleSourceSchemeFile {
			return normalizedFileModuleSource(parsed.Path)
		}
		if parsed.Scheme == "ssh" && parsed.Hostname() != "" {
			parsed = &url.URL{Scheme: "https", Host: parsed.Hostname(), Path: parsed.Path}
		}
		parsed.User = nil
		source = parsed.String()
	}
	source = strings.Replace(source, ".git//", "//", 1)
	return strings.TrimSuffix(source, ".git")
}

// httpsGitAddress rewrites the scp-like ("git@host:org/repo") and the GitHub
// or Bitbucket shorthand spellings of a git module to the https address used
// when the same repository is written in full, so a module keeps one source.
func httpsGitAddress(source string) (string, bool) {
	if at := strings.Index(source, "@"); at > 0 && !strings.Contains(source[:at], "/") {
		host, path, ok := strings.Cut(source[at+1:], ":")
		if ok && host != "" && !strings.Contains(host, "/") && !strings.HasPrefix(path, "//") {
			return "https://" + host + "/" + strings.TrimPrefix(path, "/"), true
		}
	}
	for _, prefix := range []string{"github.com/", "bitbucket.org/"} {
		if strings.HasPrefix(strings.ToLower(source), prefix) {
			return "https://" + source, true
		}
	}
	return "", false
}

func normalizedFileModuleSource(path string) string {
	path = filepath.ToSlash(filepath.Clean(path))
	if packageEnd := strings.Index(path, ".git/"); packageEnd >= 0 {
		subdir := strings.TrimPrefix(path[packageEnd+len(".git/"):], "/")
		name := filepath.Base(path[:packageEnd])
		if subdir != "" {
			return name + "//" + subdir
		}
		return name
	}
	return strings.TrimSuffix(filepath.Base(path), ".git")
}

func fileURLPath(value string) string {
	if len(value) >= 3 && value[0] == '/' && value[2] == ':' {
		value = value[1:]
	}
	return filepath.FromSlash(value)
}

func portablePathIsAbs(value string) bool {
	value = strings.ReplaceAll(value, `\`, "/")
	return strings.HasPrefix(value, "/") ||
		(len(value) >= 3 && value[1] == ':' && value[2] == '/')
}

func portablePathBase(value string) string {
	return pathpkg.Base(strings.ReplaceAll(value, `\`, "/"))
}

func declarationLocation(
	filePath string,
	startLine, endLine, startColumn, endColumn int,
	repoPath string,
) model.SourceLocation {
	if endLine < startLine {
		endLine = startLine
	}
	filename := repoRelativeFile(filePath, repoPath)
	return model.SourceLocation{
		Filename:    filename,
		LineStart:   startLine,
		LineEnd:     endLine,
		ColumnStart: startColumn,
		ColumnEnd:   endColumn,
	}
}

func pathWithinRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != parentDirectoryPath &&
		!strings.HasPrefix(rel, parentDirectoryPath+string(filepath.Separator))
}

func repoRelativeFile(filePath, repoPath string) string {
	// No repo root in content-push mode: the pushed path's shape is self-locating,
	// and relativizing against the process CWD would corrupt it (an absolute path
	// would collapse to its basename).
	if repoPath == "" {
		return filepath.ToSlash(filepath.Clean(filePath))
	}
	abs := absPath(filePath, repoPath)
	rel, err := filepath.Rel(filepath.Clean(repoPath), abs)
	if err != nil {
		return filepath.ToSlash(filepath.Base(abs))
	}
	return filepath.ToSlash(rel)
}

func moduleCallerRoot(calledFrom, repoPath string) string {
	return filepath.Clean(filepath.Dir(absPath(calledFrom, repoPath)))
}

// moduleFileName names a module file relative to the directory holding it:
// the innermost resolved package containing it, returned alongside, or the
// scanned repository.
func moduleFileName(filePath, repoPath string, packages []modulePackage) (string, modulePackage) {
	abs := absPath(filePath, repoPath)
	for i := len(packages) - 1; i >= 0; i-- {
		root := packages[i].root
		if root == "" || !pathWithinRoot(abs, root) {
			continue
		}
		if rel, err := filepath.Rel(filepath.Clean(root), abs); err == nil {
			return filepath.ToSlash(rel), packages[i]
		}
	}
	name := repoRelativeFile(abs, repoPath)
	if name == parentDirectoryPath || strings.HasPrefix(name, parentDirectoryPath+"/") {
		return pathpkg.Base(name), modulePackage{}
	}
	return name, modulePackage{}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cloneModuleAttribution(attr *model.ModuleAttribution) *model.ModuleAttribution {
	if attr == nil {
		return nil
	}
	clone := *attr
	if len(attr.ModulePath) > 0 {
		clone.ModulePath = append([]model.ModulePathHop(nil), attr.ModulePath...)
	}
	return &clone
}

func moduleAttributionKey(resourceType string, definitionLine, definitionColumn int) string {
	return resourceType + "." + strconv.Itoa(definitionLine) + "." + strconv.Itoa(definitionColumn)
}

func cloneModuleAttributions(attrs map[string]*model.ModuleAttribution) map[string]*model.ModuleAttribution {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]*model.ModuleAttribution, len(attrs))
	for key, attr := range attrs {
		out[key] = cloneModuleAttribution(attr)
	}
	return out
}

// moduleAttributionForResource returns the attribution of the resource the
// finding was raised on, with its call site narrowed to the argument setting
// the flagged line when one does, and its code location narrowed to the
// flagged region inside the module.
func moduleAttributionForResource(
	attrs map[string]*model.ModuleAttribution, v *model.Vulnerability,
) *model.ModuleAttribution {
	if len(attrs) == 0 {
		return nil
	}
	attr, ok := attrs[moduleAttributionKey(v.ResourceType, v.BlockLocation.Start.Line, v.BlockLocation.Start.Col)]
	if !ok {
		return nil
	}
	clone := cloneModuleAttribution(attr)
	if clone == nil {
		return nil
	}
	for _, arg := range clone.Arguments {
		if v.Line >= arg.LineStart && v.Line <= arg.LineEnd {
			clone.CallSite = arg.CallSite
			clone.CallArgument = true
			break
		}
	}
	clone.Arguments = nil
	narrowCodeLocation(&clone.ModuleCodeLocation, v)
	return clone
}

// narrowCodeLocation narrows the module code location to the region reports
// highlight for the finding: the remediation location when it lies within the
// vulnerable region, the vulnerable region otherwise, with a non-empty column
// range like the SARIF primary location. It is left as is when the finding
// carries no region.
func narrowCodeLocation(location *model.SourceLocation, v *model.Vulnerability) {
	region := v.VulnerabilityLocation
	if region.Start.Line < 1 {
		return
	}
	if remediation := v.RemediationLocation; remediation.Start.Line >= region.Start.Line &&
		remediation.End.Line <= region.End.Line {
		region = remediation
	}
	location.LineStart = region.Start.Line
	location.LineEnd = max(region.End.Line, region.Start.Line)
	location.ColumnStart = max(region.Start.Col, 1)
	location.ColumnEnd = region.End.Col
	if location.LineEnd == location.LineStart && location.ColumnEnd <= location.ColumnStart {
		location.ColumnEnd = location.ColumnStart + 1
	}
}
