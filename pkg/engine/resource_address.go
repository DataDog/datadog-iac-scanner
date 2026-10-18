/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/address"
)

const (
	terraformPlatformName = "Terraform"
	dataPrefix            = "data"
	resourcePrefix        = "resource"
	modulePrefix          = "module"
)

// isTerraformFile reports whether the file a finding decoded against is a
// Terraform parse.
func isTerraformFile(file *model.FileMetadata) bool {
	return file != nil && strings.EqualFold(file.Platform, terraformPlatformName)
}

// appendAddressedFindings appends a finding once per Terraform instance
// address it covers. A finding on an expanded block whose planned instances
// convert identically fans out to every address; a finding on a layer holding
// a distinct instance carries that instance's address; findings that cannot be
// pinned to an address keep the unindexed form or none at all. Other
// platforms pass through untouched.
func appendAddressedFindings(vulns []model.Vulnerability, vuln *model.Vulnerability, qCtx *QueryContext) []model.Vulnerability {
	file := qCtx.Files[vuln.FileID]
	if file != nil {
		vuln.RootModuleDir = file.RootModuleDir
	}
	if !isTerraformFile(file) {
		return append(vulns, *vuln)
	}
	addresses := resourceAddressesFor(file, vuln.SearchKey)
	if len(addresses) == 0 {
		return append(vulns, *vuln)
	}
	if len(addresses) == 1 {
		vuln.ResourceAddress = addresses[0]
		return append(vulns, *vuln)
	}
	for _, addr := range addresses {
		addressed := *vuln
		addressed.ResourceAddress = addr
		vulns = append(vulns, addressed)
	}
	return vulns
}

// resourceAddressesFor returns every Terraform instance address a finding
// with the given search key covers, in plan order.
func resourceAddressesFor(file *model.FileMetadata, searchKey string) (addresses []string) { //nolint:gocyclo
	if file == nil {
		return nil
	}
	// An instantiated-module document: the module call address prefixes every
	// resource inside it. Rules name a resource either type[instance-name] or
	// resource.<type>.<instance-name>.
	if file.ModuleAddress != "" {
		if path := moduleDocResourcePath(searchKey); path != "" {
			return []string{file.ModuleAddress + "." + path}
		}
		return nil
	}
	// A parsed terraform plan: the plan's own address is the identity.
	if addr := tfplanAddress(file, searchKey); addr != "" {
		return []string{addr}
	}
	// A plain file with expansion plans: the layer this document holds picks
	// the addresses its instance values cover (see converter.BuildLayers: a
	// later layer holds a further instance of each expanded block, or the
	// first document's value when the block has no instance there). An
	// instance-keyed search key (counted[2]) names one distinct converted
	// instance of the block, so the record is matched on the block's bare
	// name and the finding fans out to every address that instance's value
	// covers.
	mode, typ, name, identified := resourceIdentityFromSearchKey(searchKey)
	if identified {
		baseName, instanceKey := splitInstanceKey(name)
		lookupName := name
		if instanceKey != "" {
			lookupName = baseName
		}
		for _, exp := range file.Expansions {
			if exp.Type != typ || exp.Name != lookupName || (mode != "" && (mode == address.ModeData) != exp.Data) {
				continue
			}
			if instanceKey != "" {
				if addresses := expansionAddressesForInstanceKey(&exp, instanceKey); addresses != nil {
					return addresses
				}
				break
			}
			position := file.ExpansionLayer
			if position < 0 || position >= len(exp.Positions) {
				position = 0
			}
			if len(exp.Positions[position]) == 0 {
				// The layer holds the block as written (a truncated expansion's
				// as-written conversion): it stands for the block itself, not
				// for any one planned instance, so it keeps the unindexed
				// address.
				break
			}
			return exp.AddressesFor(position)
		}
	}
	// Unexpanded or unresolvable: the unindexed form Terraform uses for a
	// block without meta-arguments.
	if identified {
		return []string{address.Unindexed("", mode, typ, name)}
	}
	if path := resourcePathFromSearchKey(searchKey); path != "" {
		return []string{path}
	}
	return nil
}

// moduleDocResourcePath returns the resource path a search key names within
// a module-addressed document. Rules spell it resource.<type>.<name>...,
// data.<type>.<name>..., type[name][...] or type.name[...]; empty when the
// search key does not name a resource.
func moduleDocResourcePath(searchKey string) string {
	segments := splitTerraformPath(searchKey)
	switch {
	case segments[0] == resourcePrefix || segments[0] == dataPrefix:
		return resourcePathFromSearchKey(searchKey)
	case len(segments) >= 2:
		if idx := strings.Index(segments[0], "["); idx > 0 && strings.HasSuffix(segments[0], "]") {
			// type[instance-name]: the document key is the instance name.
			return segments[0][:idx] + "." + segments[0][idx+1:len(segments[0])-1]
		}
		return segments[0] + "." + segments[1]
	}
	return ""
}

// expansionPrefix is the address prefix an expansion record's addresses
// share: type.name for a resource block, data.type.name for a data block and
// module.name for a module call.
func expansionPrefix(exp *model.ResourceExpansion) string {
	if exp.Type == "module" {
		return "module." + exp.Name
	}
	prefix := exp.Type + "." + exp.Name
	if exp.Data {
		return "data." + prefix
	}
	return prefix
}

// expansionAddressesForInstanceKey returns every address the distinct
// converted instance whose full address is prefix+key covers: the planned
// instances that convert identically fold into one document, so a finding on
// it is reported once per address it stands for. nil when no planned instance
// has that address.
func expansionAddressesForInstanceKey(exp *model.ResourceExpansion, key string) []string {
	full := expansionPrefix(exp) + key
	for i, addr := range exp.Addresses {
		if addr != full {
			continue
		}
		if position := exp.PositionOfAddress(i); position >= 0 {
			if addresses := exp.AddressesFor(position); len(addresses) > 0 {
				return addresses
			}
		}
	}
	return nil
}

// splitInstanceKey splits a resource name into its base name and the
// instance key it carries (counted[2] → "counted", "[2]";
// keyed["a.b"] → "keyed", `["a.b"]`). key is empty when the name carries
// none.
func splitInstanceKey(name string) (base, key string) {
	inQuotes, escaped := false, false
	for i, r := range name {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case r == '[' && !inQuotes:
			// A resource name never contains a bracket, so the first one
			// opens the instance key.
			return name[:i], name[i:]
		}
	}
	return name, ""
}

// resourceIdentityFromSearchKey extracts the resource mode, type and name a
// search key names. Rules spell the identity in three shapes:
// type.name[.attr...], type[name][.attr...] and the same two with Terraform's
// resource. prefix spelled out (resource.<type>[<name>].attr); data sources
// carry the data. prefix. Template markers some rules wrap names in are
// stripped.
func resourceIdentityFromSearchKey(searchKey string) (mode address.Mode, typ, name string, ok bool) {
	segments := splitTerraformPath(searchKey)
	if segments[0] == resourcePrefix && len(segments) >= 2 {
		// The engine's documents carry no resource. prefix, so a key spelled
		// with it names the same shapes without it.
		segments = segments[1:]
	}
	first := strings.TrimSuffix(strings.TrimPrefix(segments[0], "{{"), "}}")
	if first == dataPrefix {
		if len(segments) < 3 {
			return "", "", "", false
		}
		return address.ModeData, segments[1], strings.Trim(segments[2], `"`), true
	}
	if idx := strings.Index(first, "["); idx > 0 && strings.HasSuffix(first, "]") {
		name := strings.TrimSuffix(first[idx+1:], "]")
		name = strings.Trim(name, `"`)
		name = strings.TrimSuffix(strings.TrimPrefix(name, "{{"), "}}")
		return "", first[:idx], name, true
	}
	if len(segments) >= 2 {
		return "", segments[0], segments[1], true
	}
	return "", "", "", false
}

// tfplanAddress looks up the address a parsed plan attached to a resource, by
// the flattened document key a finding's search key names.
func tfplanAddress(file *model.FileMetadata, searchKey string) string {
	segments := splitTerraformPath(searchKey)
	if len(segments) < 3 {
		return ""
	}
	var byType map[string]map[string]string
	if file.TfplanResourceAddresses != nil {
		byType = file.TfplanResourceAddresses
	} else if file.Document != nil {
		byType = tfplanAddressesFromDoc(file.Document)
	}
	if byType == nil {
		return ""
	}
	// The plan flattens child modules into Resource[type][moduleAddress.name],
	// so a module-nested finding's document key spans the segments after the
	// resource type up to the resource name and its instance key
	// (module.m.b[0]), with any attributes after it. The longest prefix that
	// names a key wins; a root-level resource's key is its plain name.
	if byKey, ok := byType[segments[1]]; ok {
		for end := len(segments); end > 2; end-- {
			if addr, ok := byKey[strings.Join(segments[2:end], ".")]; ok {
				return addr
			}
		}
	}
	return ""
}

// tfplanAddressesFromDoc extracts, per resource type and document key, the
// address a parsed plan stored under _dd_tfplan_meta.
func tfplanAddressesFromDoc(doc model.Document) map[string]map[string]string {
	raw, ok := doc["_dd_tfplan_meta"].(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]map[string]string)
	for typ, byKeyRaw := range raw {
		byKey, ok := byKeyRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for key, metaRaw := range byKey {
			meta, ok := metaRaw.(map[string]interface{})
			if !ok {
				continue
			}
			addr, _ := meta["address"].(string)
			if addr == "" {
				continue
			}
			if out[typ] == nil {
				out[typ] = make(map[string]string)
			}
			out[typ][key] = addr
		}
	}
	return out
}

// captureTfplanAddresses copies a tfplan document's address metadata into the
// file metadata before the document tree is released.
func captureTfplanAddresses(fm *model.FileMetadata) {
	if fm == nil || !isTerraformFile(fm) || fm.Document == nil {
		return
	}
	if addrs := tfplanAddressesFromDoc(fm.Document); len(addrs) > 0 {
		fm.TfplanResourceAddresses = addrs
	}
}

// resourcePathFromSearchKey returns the resource path a search key names
// (type.name[...], with the data. prefix kept), or empty when the search key
// does not name one.
func resourcePathFromSearchKey(searchKey string) string {
	segments := splitTerraformPath(searchKey)
	if len(segments) < 3 {
		return ""
	}
	switch segments[0] {
	case resourcePrefix, dataPrefix:
		return strings.Join(segments[1:3], ".")
	default:
		return ""
	}
}

// splitTerraformPath splits a document path on dots that are not part of an
// instance key, so names carrying quoted dots stay one segment
// (resource.aws_s3_bucket.b["a.b"].tags → resource / aws_s3_bucket / b["a.b"] / tags).
func splitTerraformPath(path string) []string {
	var segments []string
	var current strings.Builder
	inQuotes := false
	depth := 0
	escaped := false
	for _, r := range path {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inQuotes:
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case r == '[' && !inQuotes:
			depth++
		case r == ']' && !inQuotes && depth > 0:
			depth--
		case r == '.' && !inQuotes && depth == 0:
			segments = append(segments, current.String())
			current.Reset()
			continue
		default:
		}
		current.WriteRune(r)
	}
	segments = append(segments, current.String())
	return segments
}

// assignRootModuleDirs stamps each Terraform file with the root module
// directory it belongs to: the nearest enclosing directory that is not itself
// called as a module. Findings use it for identity, so two Terraform roots in
// one repository stay apart.
func assignRootModuleDirs(files model.FileMetadatas, calledDirs map[string]bool, repoPath string) {
	for _, f := range files {
		if f == nil || !isTerraformFile(f) {
			continue
		}
		dir := filepath.Dir(absPath(f.FilePath, repoPath))
		root := dir
		for calledDirs[filepath.Clean(root)] {
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			root = parent
		}
		if rel, err := filepath.Rel(repoPath, root); err == nil {
			f.RootModuleDir = filepath.ToSlash(rel)
		}
	}
}

// baseNamedSearchKey strips Terraform instance keys from a search key's
// first segment (aws_s3_bucket[counted[2]].acl →
// aws_s3_bucket[counted].acl), so line detection resolves against the block
// as written: the line document (a plain reparse) names blocks by their base
// name and carries no instance-addressed keys. The instance stays on the
// finding's address. Search keys whose instance name is carried in a later
// segment (aws_s3_bucket.counted[2].acl) pass through unchanged — line
// detection still resolves them through the detector's bracket handling.
func baseNamedSearchKey(searchKey string) string {
	segments := splitTerraformPath(searchKey)
	if len(segments) == 0 {
		return searchKey
	}
	first := segments[0]
	idx := strings.Index(first, "[")
	if idx <= 0 || !strings.HasSuffix(first, "]") {
		return searchKey
	}
	inner := first[idx+1 : len(first)-1]
	if base := strings.Index(inner, "["); base > 0 {
		inner = inner[:base]
	}
	inner = strings.Trim(inner, `"`)
	if inner == "" {
		return searchKey
	}
	return first[:idx] + "[" + inner + "]" + "." + strings.Join(segments[1:], ".")
}
