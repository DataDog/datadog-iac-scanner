/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package inventory

import "github.com/DataDog/datadog-iac-scanner/pkg/model"

// ProjectResource creates a schema v1 row from one declaration instance.
func ProjectResource(o *model.ResourceOccurrence) Resource {
	row := Resource{
		occurrence:   o,
		ResourcePath: o.ResourcePath,
		Platform:     o.Platform,
		ResourceType: o.ResourceType,
		ResourceName: o.ResourceName,
		Provider:     o.Provider,
		File:         o.File,
		LineStart:    o.Source.Start.Line,
		LineEnd:      o.Source.End.Line,
		ColumnStart:  o.Source.Start.Col,
		ColumnEnd:    o.Source.End.Col,
		Completeness: CompletenessComplete,
	}
	if o.Helm != nil {
		row.OriginGenerator = "helm"
		row.OriginChartPath = o.Helm.ChartPath
		row.OriginChartName = o.Helm.ChartName
		row.OriginChartVersion = o.Helm.ChartVersion
		row.OriginTemplate = o.Helm.Template
	}
	if o.Terraform != nil {
		row.RootModule = o.Terraform.Root
		row.ResourcePath = o.Terraform.Address
		row.ModuleCall = o.Terraform.ModuleCall
		if !o.Terraform.Complete {
			row.Completeness = CompletenessInstanceUnresolved
		}
	}
	return row
}
