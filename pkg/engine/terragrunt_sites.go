/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/tfeval"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// isTerraformSource reports whether f is a file the module evaluation roots
// or strips: Terraform configuration, or a Terragrunt unit with a translation.
func isTerraformSource(f *model.FileMetadata) bool {
	return f != nil && (tfpath.IsConfig(f.FilePath) || f.TerragruntTranslation != nil)
}

// unitSite is a translation served as a virtual file, and the unit it stands for.
type unitSite struct {
	unit  string
	table model.LineTable
}

// unitSites maps the virtual files of Terragrunt translations back to the real
// files they were written from. A nil *unitSites maps nothing.
type unitSites struct {
	repoPath string
	byFile   map[string]*unitSite
}

// overlayTranslations serves each translation of files as a virtual file in
// the directory of its unit, over fsys. Without translation it returns fsys
// and no sites.
func overlayTranslations(files model.FileMetadatas, repoPath string, fsys vfs.FS) (vfs.FS, *unitSites) {
	var contents map[string][]byte
	var sites *unitSites
	for _, f := range files {
		if f == nil || f.TerragruntTranslation == nil {
			continue
		}
		if fsys == nil {
			fsys = vfs.Default()
		}
		if sites == nil {
			contents = make(map[string][]byte)
			sites = &unitSites{repoPath: repoPath, byFile: make(map[string]*unitSite)}
		}
		t := f.TerragruntTranslation
		unit := absPath(f.FilePath, repoPath)
		virtual := filepath.Join(filepath.Dir(unit), freeFileName(fsys, filepath.Dir(unit), t.FileName))
		contents[virtual] = []byte(t.Text)
		sites.byFile[absPath(virtual, repoPath)] = &unitSite{unit: unit, table: t.Lines}
	}
	if sites == nil {
		return fsys, nil
	}
	return vfs.NewOverlay(fsys, contents), sites
}

// freeFileName returns name, or a variant of it no file of dir already uses.
func freeFileName(fsys vfs.FS, dir, name string) string {
	candidate := name
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		if _, err := fsys.Stat(filepath.Join(dir, candidate)); err != nil {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d%s", stem, i, ext)
	}
}

func (s *unitSites) lookup(file string) *unitSite {
	if s == nil || file == "" {
		return nil
	}
	return s.byFile[absPath(file, s.repoPath)]
}

// real returns the real location holding a virtual line: the item that set the
// argument written there, else the unit's terraform.source anchor.
func (u *unitSite) real(line int) model.SourceLocation {
	if m, ok := u.table.LookupOrAnchor(line); ok {
		return m.Real
	}
	return model.SourceLocation{Filename: u.unit, LineStart: line, LineEnd: line}
}

func (s *unitSites) file(r model.SourceLocation, u *unitSite) string {
	if r.Filename == "" {
		return u.unit
	}
	return absPath(r.Filename, s.repoPath)
}

// callRange maps a call site read from the evaluator to where it is written
// (absolute file): a call of a translation points at the unit's
// terraform.source attribute.
func (s *unitSites) callRange(site *tfeval.CallSite) model.SourceLocation {
	u := s.lookup(site.CalledFrom)
	if u == nil {
		return model.SourceLocation{
			Filename: site.CalledFrom, LineStart: site.CalledLine, LineEnd: site.CalledEndLine,
			ColumnStart: site.CalledColumn, ColumnEnd: site.CalledEndColumn,
		}
	}
	rng := u.real(site.CalledLine)
	rng.Filename = s.file(rng, u)
	return rng
}

// callFile is the file that holds a module call: the unit file when the call
// is a translation, else the file the call is written in.
func (s *unitSites) callFile(site *tfeval.CallSite) string {
	if u := s.lookup(site.CalledFrom); u != nil {
		return u.unit
	}
	return site.CalledFrom
}

// attributeLocation is the location of a module call argument, in the file
// that sets it when the call is a translation.
func (s *unitSites) attributeLocation(attr *hclsyntax.Attribute, filename string) model.SourceLocation {
	if u := s.lookup(attr.SrcRange.Filename); u != nil {
		rng := u.real(attr.SrcRange.Start.Line)
		return declarationLocation(s.file(rng, u), rng.LineStart, rng.LineEnd,
			rng.ColumnStart, rng.ColumnEnd, s.repoPath)
	}
	return model.SourceLocation{
		Filename:    filename,
		LineStart:   attr.SrcRange.Start.Line,
		LineEnd:     attr.SrcRange.End.Line,
		ColumnStart: attr.SrcRange.Start.Column,
		ColumnEnd:   attr.SrcRange.End.Column,
	}
}
