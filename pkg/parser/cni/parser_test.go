/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package cni

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestParser_ParseSupportedExtensions(t *testing.T) {
	parser := &Parser{}

	for _, extension := range parser.SupportedExtensions() {
		t.Run(extension, func(t *testing.T) {
			content := []byte(`{"cniVersion":"1.0.0","type":"bridge"}`)
			if extension == ".conflist" {
				content = []byte(`{"cniVersion":"1.0.0","plugins":[{"type":"bridge"}]}`)
			}
			_, documents, _, _, err := parser.Parse(context.Background(), content, "10-bridge"+extension, false, 15)
			require.NoError(t, err)
			require.Len(t, documents, 1)
			require.Equal(t, "1.0.0", documents[0]["cniVersion"])
			require.Contains(t, documents[0], "_dd_lines")
			if extension == ".conflist" {
				require.Contains(t, documents[0], "plugins")
			}
		})
	}
}

func TestParser_SkipsNonCNIJSON(t *testing.T) {
	parser := &Parser{}

	_, documents, _, _, err := parser.Parse(
		context.Background(),
		[]byte(`{"description":"cniVersion type"}`),
		"not-cni.conf",
		false,
		15,
	)

	require.NoError(t, err)
	require.Empty(t, documents)
}

func TestParser_KindAndSupportedTypes(t *testing.T) {
	parser := &Parser{}
	require.Equal(t, model.KindJSON, parser.GetKind())
	require.Equal(t, map[string]bool{"kubernetes": true}, parser.SupportedTypes())
}
