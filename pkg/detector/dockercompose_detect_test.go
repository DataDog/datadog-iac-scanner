/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/stretchr/testify/require"
)

func TestComposeSearchPath(t *testing.T) {
	require.Equal(t, []string{"services", "web", "image"}, ComposeSearchPath("services.web.image"))
	require.Equal(t, []string{"services", "web", "image"}, ComposeSearchPath("services.web.image=nginx:latest"))
	require.Equal(t, []string{"services", "web", "ports", "0"}, ComposeSearchPath("services.web.ports.0"))
	// A platform prefix not part of the document is dropped by the caller's
	// second attempt, but ComposeSearchPath itself keeps the components.
	require.Equal(t, []string{"dockerCompose", "services", "web", "image"}, ComposeSearchPath("dockerCompose.services.web.image"))
}

func TestDockerComposeDetectLine_StructuralLookup(t *testing.T) {
	// web inherits `image` from base via extends: the document has an exact
	// _dd_lines marker (line 3), while text matching would walk on to db's
	// image on line 8.
	doc := model.Document{
		"services": model.Document{
			"base": model.Document{
				"_dd_lines": lineInfo(3),
				"image":     "nginx:latest",
			},
			"web": model.Document{
				"_dd_lines": lineInfo(4),
				"image":     "nginx:latest",
			},
		},
		"_dd_lines": lineInfo(1),
	}
	// Give web's image its own line info entry the way UnmarshalYAML would.
	web := doc["services"].(model.Document)["web"].(model.Document)
	web["_dd_lines"] = model.Document{
		"_dd__default": &model.LineObject{Line: 4},
		"_dd_image":    &model.LineObject{Line: 3},
	}
	lines := []string{
		"services:",
		"  base:",
		"    image: nginx:latest",
		"  web:",
		"    extends:",
		"      service: base",
		"  db:",
		"    image: postgres:16",
	}
	file := &model.FileMetadata{
		Platform:          "dockercompose",
		LineInfoDocument:  doc,
		LinesOriginalData: &lines,
	}

	d := DockerComposeDetectLine{}
	result := d.DetectLine(context.Background(), file, "services.web.image", 3)
	require.Equal(t, 3, result.Line, "structural _dd_lines lookup must win over text walking")

	// Without a platform match the default text matcher applies.
	file.Platform = "kubernetes"
	result = d.DetectLine(context.Background(), file, "services.web.image", 3)
	require.Equal(t, 8, result.Line, "non-compose YAML keeps default text matching")
}

func TestDockerComposeDetectLine_FallbackOnMissingMarker(t *testing.T) {
	doc := model.Document{
		"services": model.Document{
			"web": model.Document{"image": "nginx:latest"},
		},
	}
	lines := []string{"services:", "  web:", "    image: nginx:latest"}
	file := &model.FileMetadata{
		Platform:          "dockercompose",
		LineInfoDocument:  doc,
		LinesOriginalData: &lines,
	}
	d := DockerComposeDetectLine{}
	result := d.DetectLine(context.Background(), file, "services.web.image", 3)
	require.Equal(t, 3, result.Line, "text matching is the fallback when _dd_lines lack the key")
}

func lineInfo(line int) model.Document {
	return model.Document{"_dd__default": &model.LineObject{Line: line}}
}

func TestComposeSearchPath_SkipsEmptyComponents(t *testing.T) {
	// Empty path components (trailing/consecutive dots in a search key) must
	// not survive expansion: they never match a document path.
	require.Equal(t, []string{"services", "image"}, ComposeSearchPath("services..image"))
	require.Equal(t, []string{"services"}, ComposeSearchPath("services."))
}
