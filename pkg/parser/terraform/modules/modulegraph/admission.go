/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package modulegraph

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules/resolver"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
)

func moduleAdmissionLimit(request *Request) (maximum, baseline int64, enforce bool) {
	if request.ResourceLimits.MaxTotalBytes > 0 {
		maximum = request.ResourceLimits.MaxTotalBytes
		enforce = true
	}
	if request.TotalParseBytes <= 0 {
		return maximum, 0, enforce
	}
	fsys := request.FS
	if fsys == nil {
		fsys = vfs.Default()
	}
	seen := make(map[string]bool, len(request.BaselinePaths))
	for _, path := range request.BaselinePaths {
		clean := filepath.Clean(path)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		info, err := fsys.Stat(clean)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		baseline += info.Size()
	}
	available := max(int64(0), request.TotalParseBytes-baseline)
	if !enforce || available < maximum {
		maximum = available
	}
	return maximum, baseline, true
}

type admissionNode struct {
	root     string
	source   string
	depth    int
	direct   bool
	parents  map[string]bool
	children map[string]bool
	usage    resolver.PackageUsage
}

func shedToTotalLimit(
	snapshot *walkerSnapshot, budget *resolver.ResourceBudget, maximum int64, enforce bool,
) {
	if !enforce || budget.TotalUsage().Bytes <= maximum {
		return
	}
	nodes := admissionNodes(snapshot.modules, budget)
	accepted := make(map[string]bool, len(nodes))
	for root := range nodes {
		accepted[root] = true
	}

	rank := 0
	currentBytes := admittedBytes(nodes, accepted)
	hasCycles := admissionGraphHasCycles(nodes)
	for _, candidate := range sheddingOrder(nodes) {
		if currentBytes <= maximum {
			break
		}
		if !accepted[candidate] {
			continue
		}
		removed := removeAdmissionSubtree(nodes, accepted, candidate)
		if hasCycles && removalMayOrphan(nodes, accepted, removed) {
			removed = append(removed, pruneUnreachableAdmissionNodes(nodes, accepted)...)
			sortRemovedNodes(nodes, removed, candidate)
		}
		measured := currentBytes
		for _, root := range removed {
			rank++
			node := nodes[root]
			currentBytes -= node.usage.Bytes
			snapshot.budgetEvents = append(snapshot.budgetEvents, BudgetEvent{
				Source:       node.source,
				Gate:         "pre_parse_admission",
				Limit:        "module_bytes_total",
				Maximum:      maximum,
				Measured:     measured,
				SheddingRank: rank,
			})
		}
	}

	roots := packageRootsBySpecificity(nodes)
	snapshot.paths = filterPathsByPackages(snapshot.paths, roots, accepted)
	snapshot.modules = filterModulesByPackages(snapshot.modules, accepted)
	for localPath := range snapshot.sourceMappings {
		if !pathOwnedByAcceptedPackage(localPath, roots, accepted) {
			delete(snapshot.sourceMappings, localPath)
		}
	}
}

func admissionNodes(modules []ResolvedModule, budget *resolver.ResourceBudget) map[string]*admissionNode {
	nodes := make(map[string]*admissionNode)
	for i := range modules {
		module := &modules[i]
		root := filepath.Clean(module.PackageRoot)
		node := nodes[root]
		if node == nil {
			usage, _ := budget.Usage(root)
			node = &admissionNode{
				root:     root,
				source:   module.CanonicalSource,
				depth:    module.Depth,
				parents:  make(map[string]bool),
				children: make(map[string]bool),
				usage:    usage,
			}
			nodes[root] = node
		}
		if module.CanonicalSource < node.source {
			node.source = module.CanonicalSource
		}
		if module.Depth > node.depth {
			node.depth = module.Depth
		}
		parent := filepath.Clean(module.ParentPackageRoot)
		if module.ParentPackageRoot == "" {
			node.direct = true
			continue
		}
		node.parents[parent] = true
	}
	for root, node := range nodes {
		for parent := range node.parents {
			if parentNode := nodes[parent]; parentNode != nil {
				parentNode.children[root] = true
			}
		}
	}
	return nodes
}

func admittedBytes(nodes map[string]*admissionNode, accepted map[string]bool) int64 {
	var total int64
	for root := range accepted {
		total += nodes[root].usage.Bytes
	}
	return total
}

func sheddingOrder(nodes map[string]*admissionNode) []string {
	order := make([]string, 0, len(nodes))
	subtreeBytes := make(map[string]int64, len(nodes))
	for root := range nodes {
		order = append(order, root)
		subtreeBytes[root] = admissionSubtreeBytes(nodes, root)
	}
	sort.Slice(order, func(i, j int) bool {
		left, right := nodes[order[i]], nodes[order[j]]
		if left.direct != right.direct {
			return !left.direct
		}
		if left.depth != right.depth {
			return left.depth > right.depth
		}
		if subtreeBytes[left.root] != subtreeBytes[right.root] {
			return subtreeBytes[left.root] > subtreeBytes[right.root]
		}
		if left.source != right.source {
			return left.source < right.source
		}
		return left.root < right.root
	})
	return order
}

func admissionSubtreeBytes(nodes map[string]*admissionNode, root string) int64 {
	seen := make(map[string]bool)
	queue := []string{root}
	var total int64
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		total += nodes[current].usage.Bytes
		for child := range nodes[current].children {
			queue = append(queue, child)
		}
	}
	return total
}

func removeAdmissionSubtree(
	nodes map[string]*admissionNode, accepted map[string]bool, candidate string,
) []string {
	queue := []string{candidate}
	removed := make([]string, 0, 1)
	for len(queue) > 0 {
		root := queue[0]
		queue = queue[1:]
		if !accepted[root] {
			continue
		}
		delete(accepted, root)
		removed = append(removed, root)
		for child := range nodes[root].children {
			if !accepted[child] || nodes[child].direct || hasAcceptedParent(nodes[child], accepted) {
				continue
			}
			queue = append(queue, child)
		}
	}
	sortRemovedNodes(nodes, removed, candidate)
	return removed
}

func sortRemovedNodes(nodes map[string]*admissionNode, removed []string, candidate string) {
	sort.Slice(removed, func(i, j int) bool {
		if removed[i] == candidate {
			return true
		}
		if removed[j] == candidate {
			return false
		}
		left, right := nodes[removed[i]], nodes[removed[j]]
		if left.depth != right.depth {
			return left.depth > right.depth
		}
		if left.source != right.source {
			return left.source < right.source
		}
		return left.root < right.root
	})
}

func hasAcceptedParent(node *admissionNode, accepted map[string]bool) bool {
	for parent := range node.parents {
		if accepted[parent] {
			return true
		}
	}
	return false
}

func admissionGraphHasCycles(nodes map[string]*admissionNode) bool {
	indegree := make(map[string]int, len(nodes))
	queue := make([]string, 0, len(nodes))
	for root, node := range nodes {
		for parent := range node.parents {
			if nodes[parent] != nil {
				indegree[root]++
			}
		}
	}
	for root := range nodes {
		if indegree[root] == 0 {
			queue = append(queue, root)
		}
	}
	visited := 0
	for len(queue) > 0 {
		root := queue[0]
		queue = queue[1:]
		visited++
		for child := range nodes[root].children {
			indegree[child]--
			if indegree[child] == 0 {
				queue = append(queue, child)
			}
		}
	}
	return visited != len(nodes)
}

// removalMayOrphan reports whether this removal could have cut the last path
// from a direct module to a still-accepted node. Only a child of a removed node
// can lose its last path, so when no removed node has an accepted child the
// full reachability sweep can be skipped.
func removalMayOrphan(
	nodes map[string]*admissionNode, accepted map[string]bool, removed []string,
) bool {
	for _, root := range removed {
		for child := range nodes[root].children {
			if accepted[child] {
				return true
			}
		}
	}
	return false
}

func pruneUnreachableAdmissionNodes(
	nodes map[string]*admissionNode, accepted map[string]bool,
) []string {
	reachable := make(map[string]bool, len(accepted))
	queue := make([]string, 0, len(accepted))
	for root := range accepted {
		if nodes[root].direct {
			reachable[root] = true
			queue = append(queue, root)
		}
	}
	for len(queue) > 0 {
		root := queue[0]
		queue = queue[1:]
		for child := range nodes[root].children {
			if accepted[child] && !reachable[child] {
				reachable[child] = true
				queue = append(queue, child)
			}
		}
	}
	removed := make([]string, 0, len(accepted)-len(reachable))
	for root := range accepted {
		if !reachable[root] {
			delete(accepted, root)
			removed = append(removed, root)
		}
	}
	return removed
}

func packageRootsBySpecificity(nodes map[string]*admissionNode) []string {
	roots := make([]string, 0, len(nodes))
	for root := range nodes {
		roots = append(roots, root)
	}
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) != len(roots[j]) {
			return len(roots[i]) > len(roots[j])
		}
		return roots[i] < roots[j]
	})
	return roots
}

func filterPathsByPackages(paths, roots []string, accepted map[string]bool) []string {
	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		if pathOwnedByAcceptedPackage(path, roots, accepted) {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func filterModulesByPackages(modules []ResolvedModule, accepted map[string]bool) []ResolvedModule {
	filtered := make([]ResolvedModule, 0, len(modules))
	for i := range modules {
		module := &modules[i]
		if accepted[filepath.Clean(module.PackageRoot)] {
			filtered = append(filtered, *module)
		}
	}
	return filtered
}

func pathOwnedByAcceptedPackage(path string, roots []string, accepted map[string]bool) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range roots {
		if cleanPath == root || strings.HasPrefix(cleanPath, root+string(filepath.Separator)) {
			return accepted[root]
		}
	}
	return false
}
