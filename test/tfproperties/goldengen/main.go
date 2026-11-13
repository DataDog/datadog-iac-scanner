/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Command goldengen writes the legacy-document goldens of the fixture
// corpus: one normalized document file per generated cell, under -out.
//
// Run it from a checkout of the engine whose documents the goldens should
// hold. On this repository's main branch, the documents are what the parser
// produces; only this file needs adapting there (see the README next to the
// goldens).
//
//	go run ./test/tfproperties/goldengen -out <dir>
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/project"
	"github.com/DataDog/datadog-iac-scanner/pkg/terraform/value"
	"github.com/DataDog/datadog-iac-scanner/test/tfcorpus"
)

// corpusCells assembles the cells the goldens cover: the expansion grid, a
// sample of the value grid, and the attribute-state cells. It must match the
// grids the golden test reads.
func corpusCells() ([]tfcorpus.Cell, []tfcorpus.StateCell) {
	cells := tfcorpus.ExpansionGrid()
	cells = append(cells, tfcorpus.CellsSample(tfcorpus.ValueGrid(), 13)...)
	return cells, tfcorpus.StateGrid()
}

// docsOfRoot builds the legacy documents of one root as the engine feeds
// them to rules.
func docsOfRoot(root string) ([]map[string]any, error) {
	scan, err := model.Load(context.Background(), root, &model.Options{})
	if err != nil {
		return nil, err
	}
	docs := project.LegacyDocs(scan.Roots, project.LegacyOptions{
		Base:        root,
		Placeholder: value.NewPlaceholder(),
		FileID:      func(string) (string, bool) { return "doc", true },
	})
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.Doc)
	}
	return out, nil
}

func main() {
	out := flag.String("out", "", "directory to write the golden files to")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	cells, stateCells := corpusCells()

	write := func(name string, root string, docs []map[string]any) error {
		if len(docs) == 0 {
			return nil
		}
		return tfcorpus.WriteGolden(filepath.Join(*out, name+".json"), tfcorpus.NormalizeDocs(root, docs))
	}

	dir, _, err := tfcorpus.MaterializeAt("", cells)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i, cell := range cells {
		root := dir + "/" + tfcorpus.DirName(i, cell.Name())
		docs, err := docsOfRoot(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, cell.Name(), err)
			os.Exit(1)
		}
		if err := write(tfcorpus.DirName(i, cell.Name()), root, docs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	stateDir, _, err := tfcorpus.MaterializeStateAt("", stateCells)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i, cell := range stateCells {
		root := stateDir + "/" + tfcorpus.DirName(i, cell.Name())
		docs, err := docsOfRoot(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, cell.Name(), err)
			os.Exit(1)
		}
		if err := write(tfcorpus.DirName(i, cell.Name()), root, docs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Println("wrote goldens to", *out)
}
