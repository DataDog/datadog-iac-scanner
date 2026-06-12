/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
)

// SchemaVersion is bumped on backward-incompatible changes.
// The JSON Schema lives at docs/schemas/iac-resource-inventory-v1.schema.json.
const SchemaVersion = "1.0"

// Inventory is the top-level IaC resource inventory document.
type Inventory struct {
	SchemaVersion string           `json:"schema_version"`
	Tool          InventoryTool    `json:"tool"`
	GeneratedAt   string           `json:"generated_at"`
	RootPath      string           `json:"root_path,omitempty"`
	ResourceCount int              `json:"resource_count"`
	Resources     []InventoryEntry `json:"resources"`
}

type InventoryTool struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// InventoryEntry is a single resource in the inventory.
type InventoryEntry struct {
	Address       string                 `json:"address"`
	IaCPlatform   string                 `json:"iac_platform"`
	BlockType     string                 `json:"block_type"`
	ResourceType  *string                `json:"resource_type"` // null for module blocks
	Name          string                 `json:"name"`
	Provider      string                 `json:"provider,omitempty"`
	FilePath      string                 `json:"file_path"`
	LineRange     LineRange              `json:"line_range"`
	ModuleSource  string                 `json:"module_source,omitempty"`
	ModuleVersion string                 `json:"module_version,omitempty"`
	APIVersion    string                 `json:"api_version,omitempty"`
	Namespace     string                 `json:"namespace,omitempty"`
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
}

// LineRange is the 1-based line span of a resource. End is best-effort.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

func BuildInventory(resources []Resource, rootPath string) *Inventory {
	entries := make([]InventoryEntry, 0, len(resources))
	for i := range resources {
		entries = append(entries, toEntry(&resources[i]))
	}

	return &Inventory{
		SchemaVersion: SchemaVersion,
		Tool: InventoryTool{
			Name:    "Datadog IaC Scanner",
			Vendor:  "Datadog",
			Version: constants.Version,
		},
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RootPath:      rootPath,
		ResourceCount: len(entries),
		Resources:     entries,
	}
}

func toEntry(r *Resource) InventoryEntry {
	var resourceType *string
	if r.Type != "" {
		resourceType = &r.Type
	}
	return InventoryEntry{
		Address:       resourceAddress(r),
		IaCPlatform:   r.Platform,
		BlockType:     string(r.BlockType),
		ResourceType:  resourceType,
		Name:          r.Name,
		Provider:      r.Provider,
		FilePath:      r.File,
		LineRange:     LineRange{Start: r.StartLine, End: r.EndLine},
		ModuleSource:  r.ModuleSource,
		ModuleVersion: r.ModuleVersion,
		APIVersion:    r.APIVersion,
		Namespace:     r.Namespace,
		Attributes:    r.Attributes,
	}
}

func resourceAddress(r *Resource) string {
	switch r.BlockType {
	case BlockModule:
		return fmt.Sprintf("module.%s", r.Name)
	case BlockData:
		return fmt.Sprintf("data.%s.%s", r.Type, r.Name)
	case BlockManifest:
		// kubectl-style <namespace>/<kind>/<name>; omit namespace for cluster-scoped objects.
		if r.Namespace != "" {
			return fmt.Sprintf("%s/%s/%s", r.Namespace, r.Type, r.Name)
		}
		return fmt.Sprintf("%s/%s", r.Type, r.Name)
	case BlockTask:
		if r.Name != "" {
			return r.Name
		}
		return r.Type
	case BlockStage, BlockJob:
		return r.Name
	case BlockResource:
		// CloudFormation uses its logical ID; Terraform uses type.name.
		if r.Platform == platformCloudFormation {
			return r.Name
		}
		return fmt.Sprintf("%s.%s", r.Type, r.Name)
	default:
		return fmt.Sprintf("%s.%s", r.Type, r.Name)
	}
}
