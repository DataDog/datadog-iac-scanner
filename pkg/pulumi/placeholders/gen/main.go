/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Command gen writes the invoke placeholder table (invokes.json.gz) and its
// provenance (invokes.meta.json) from the pinned Pulumi provider schemas.
//
//	go run ./pkg/pulumi/placeholders/gen -out-dir pkg/pulumi/placeholders [-schema-dir <dir with <provider>-v<version>.schema.json>]
//
// make generate-pulumi-placeholders runs it from the repository root.
//
// Schemas are downloaded from GitHub unless found in -schema-dir. Each one is
// checked against its pinned sha256.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/placeholders/schemagen"
)

const (
	downloadTimeout = 10 * time.Minute
	filePerm        = 0o600
)

type meta struct {
	Generator string           `json:"generator"`
	Providers []providerSource `json:"providers"`
	Functions int              `json:"functions"`
}

type providerSource struct {
	schemagen.Pin
	URL       string `json:"url"`
	Functions int    `json:"functions"`
}

func main() {
	outDir := flag.String("out-dir", ".", "directory to write invokes.json.gz and invokes.meta.json to")
	schemaDir := flag.String("schema-dir", "", "optional directory with already downloaded schemas")
	flag.Parse()
	if err := run(*outDir, *schemaDir); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(outDir, schemaDir string) error {
	table := map[string]map[string]any{}
	m := meta{Generator: "pkg/pulumi/placeholders/gen"}
	for _, pin := range schemagen.Pins {
		raw, err := load(pin, schemaDir)
		if err != nil {
			return err
		}
		var s schemagen.Schema
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%s v%s: %w", pin.Provider, pin.Version, err)
		}
		fns := schemagen.Build(pin.Provider, &s)
		for tok, v := range fns {
			table[tok] = v
		}
		m.Providers = append(m.Providers, providerSource{Pin: pin, URL: pin.URL(), Functions: len(fns)})
	}
	m.Functions = len(table)

	data, err := json.Marshal(table) // map keys are sorted: the output is deterministic
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	w, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "invokes.json.gz"), gz.Bytes(), filePerm); err != nil {
		return err
	}
	metaJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "invokes.meta.json"), append(metaJSON, '\n'), filePerm)
}

func load(pin schemagen.Pin, schemaDir string) ([]byte, error) {
	var raw []byte
	if schemaDir != "" {
		path := filepath.Join(schemaDir, fmt.Sprintf("%s-v%s.schema.json", pin.Provider, pin.Version))
		b, err := os.ReadFile(path) //nolint:gosec // a directory given on the command line; the content is checked by sha256

		if err == nil {
			raw = b
		}
	}
	if raw == nil {
		b, err := download(pin.URL())
		if err != nil {
			return nil, err
		}
		raw = b
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pin.SHA256 {
		return nil, fmt.Errorf("%s v%s: sha256 %s, want %s", pin.Provider, pin.Version, got, pin.SHA256)
	}
	return raw, nil
}

func download(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
