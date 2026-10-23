/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Command tfscale generates the Terraform scale fixtures, benchmarks a scanner
// binary on them, and compares two benchmark result files.
//
//	tfscale gen     -out DIR [-shapes a,b]
//	tfscale bench   -scanner BIN (-rules DIR | -bundle DIR) -fixtures DIR -out FILE [-label L] [-shapes a,b]
//	tfscale compare -base FILE -head FILE [-max-rss-ratio R] [-max-cpu-ratio R]
//	tfscale list
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DataDog/datadog-iac-scanner/test/tfscale"
)

const (
	defaultTimeout     = 90 * time.Minute
	defaultMaxRSSRatio = 1.15
	defaultMaxCPURatio = 1.25
	resultPerms        = 0o600
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = gen(os.Args[2:])
	case "bench":
		err = bench(os.Args[2:])
	case "compare":
		err = compare(os.Args[2:])
	case "list":
		catalog := tfscale.Catalog()
		for i := range catalog {
			e := tfscale.Expect(&catalog[i])
			fmt.Printf("%-28s module_instances=%-8d leaf_instances=%d\n", catalog[i].Name, e.ModuleInstances, e.LeafInstances)
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tfscale:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tfscale gen|bench|compare|list [flags]")
	os.Exit(2)
}

func selectShapes(list string) ([]tfscale.Shape, error) {
	if list == "" || list == "all" {
		return tfscale.Catalog(), nil
	}
	var out []tfscale.Shape
	for _, name := range strings.Split(list, ",") {
		s, ok := tfscale.Lookup(strings.TrimSpace(name))
		if !ok {
			return nil, fmt.Errorf("unknown shape %q", name)
		}
		out = append(out, s)
	}
	return out, nil
}

func gen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	out := fs.String("out", "", "directory to write fixtures under")
	shapes := fs.String("shapes", "all", "comma-separated shape names")
	_ = fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	selected, err := selectShapes(*shapes)
	if err != nil {
		return err
	}
	for i := range selected {
		s := &selected[i]
		dir := filepath.Join(*out, s.Name)
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		e, err := tfscale.Generate(dir, s)
		if err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(*out, s.Name+".expected.json"), e); err != nil {
			return err
		}
		if err := tfscale.PrepareRepo(context.Background(), dir); err != nil {
			return err
		}
		fmt.Printf("%-28s %8d bytes  leaf_instances=%d\n", s.Name, e.SourceBytes, e.LeafInstances)
	}
	return nil
}

func bench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	scanner := fs.String("scanner", "", "scanner binary")
	rules := fs.String("rules", "", "rule bundle with queries/ and libraries/")
	bundle := fs.String("bundle", "", "offline bundle written by `fetch-bundle`, instead of -rules")
	fixtures := fs.String("fixtures", "", "directory tfscale gen wrote")
	out := fs.String("out", "", "result file")
	label := fs.String("label", "", "label stored with each run")
	shapes := fs.String("shapes", "all", "comma-separated shape names")
	timeout := fs.Duration("timeout", defaultTimeout, "per-shape timeout")
	_ = fs.Parse(args)
	if *scanner == "" || (*rules == "") == (*bundle == "") || *fixtures == "" || *out == "" {
		return fmt.Errorf("-scanner, one of -rules or -bundle, -fixtures and -out are required")
	}
	selected, err := selectShapes(*shapes)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "tfscale-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	var runs []tfscale.Run
	for i := range selected {
		s := &selected[i]
		expected := tfscale.Expect(s)
		run, err := tfscale.Measure(context.Background(), *scanner, tfscale.Rules{Dir: *rules, Bundle: *bundle},
			filepath.Join(*fixtures, s.Name), work, &expected, *timeout)
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		run.Label = *label
		runs = append(runs, run)
		fmt.Printf("%-28s wall=%7.1fs cpu=%7.1fs rss=%6d MiB findings=%-7d complete=%t %v\n",
			s.Name, run.WallSeconds, run.CPUSeconds, tfscale.MiB(run.PeakRSS), run.Findings, run.Complete, run.Problems)
		// Written after every shape so a long run keeps what it measured.
		if err := writeJSON(*out, runs); err != nil {
			return err
		}
	}
	return nil
}

func compare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	basePath := fs.String("base", "", "baseline result file")
	headPath := fs.String("head", "", "head result file")
	rss := fs.Float64("max-rss-ratio", defaultMaxRSSRatio, "fail when head peak RSS exceeds base by this ratio")
	cpu := fs.Float64("max-cpu-ratio", defaultMaxCPURatio, "fail when head CPU time exceeds base by this ratio")
	_ = fs.Parse(args)
	var base, head []tfscale.Run
	if err := readJSON(*basePath, &base); err != nil {
		return err
	}
	if err := readJSON(*headPath, &head); err != nil {
		return err
	}
	byShape := map[string]*tfscale.Run{}
	for i := range base {
		byShape[base[i].Shape] = &base[i]
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "shape\tbase wall\thead wall\tbase cpu\thead cpu\tbase rss MiB\thead rss MiB\t"+
		"base findings\thead findings\tbase complete\thead complete")
	for i := range head {
		h := &head[i]
		b := byShape[h.Shape]
		if b == nil {
			b = &tfscale.Run{}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%.1f\t%.1f\t%.1f\t%.1f\t%d\t%d\t%d\t%d\t%t\t%t\n", h.Shape,
			b.WallSeconds, h.WallSeconds, b.CPUSeconds, h.CPUSeconds, tfscale.MiB(b.PeakRSS), tfscale.MiB(h.PeakRSS),
			b.Findings, h.Findings, b.Complete, h.Complete)
	}
	_ = tw.Flush()
	if failures := tfscale.Compare(base, head, tfscale.Thresholds{MaxRSSRatio: *rss, MaxCPURatio: *cpu}); len(failures) > 0 {
		return fmt.Errorf("regressions:\n  %s", strings.Join(failures, "\n  "))
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), resultPerms)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // a result file named on the command line
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
