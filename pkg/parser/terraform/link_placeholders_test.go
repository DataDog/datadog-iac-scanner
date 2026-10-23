/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terraform

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestParseUnavailableJSONLinkPlaceholder(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "main.tf.json")
	placeholder := []byte("./missing.tf")
	require.NoError(t, os.WriteFile(path, placeholder, 0o644))
	var logs bytes.Buffer
	log := zerolog.New(&logs).Level(zerolog.DebugLevel)
	_, docs, _, _, err := NewDefault().Parse(log.WithContext(t.Context()), placeholder, path, false, 0)
	require.NoError(t, err)
	require.Empty(t, docs)
	require.Contains(t, logs.String(), `"level":"debug"`)
}
