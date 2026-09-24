/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package dockercompose

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/yaml/dockercompose/names"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// parseCompose writes the files into a temp dir, parses the compose file with
// the real parser, and returns the cleaned (no _dd_lines/_path) documents as
// pretty JSON for JSONEq comparison.
func parseCompose(t *testing.T, composeName, composeContent string, siblings map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range siblings {
		full := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}
	composePath := filepath.Join(dir, composeName)
	require.NoError(t, os.WriteFile(composePath, []byte(composeContent), 0o600))

	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(composeContent), composePath, true, 15)
	require.NoError(t, err)
	out := make([]string, len(docs))
	for i, doc := range docs {
		j, err := json.Marshal(stripValue(doc))
		require.NoError(t, err)
		out[i] = string(j)
	}
	return out
}

func TestParse_OverrideMerge(t *testing.T) {
	base := `
services:
  web:
    image: nginx:1.27
    privileged: true
    ports:
      - "8080:80"
`
	override := `
services:
  web:
    privileged: false
    ports:
      - "9090:90"
  sidecar:
    image: vault:1.15
`

	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "image": "nginx:1.27",
	      "privileged": false,
	      "ports": ["8080:80", "9090:90"]
	    },
	    "sidecar": {"image": "vault:1.15"}
	  }
	}`, got[0], "override wins scalars, ports union, new services appended")
}

func TestParse_OverrideMerge_OtherBaseAndExt(t *testing.T) {
	base := "services:\n  web:\n    image: nginx:latest\n"
	override := "services:\n  web:\n    image: nginx:1.27\n"
	got := parseCompose(t, "docker-compose.yml", base, map[string]string{
		"docker-compose.override.yml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{"services":{"web":{"image":"nginx:1.27"}}}`, got[0])
}

func TestParse_OverrideNotAppliedToNonDefaultName(t *testing.T) {
	// Custom compose files (compose.prod.yaml) are separate -f documents,
	// not auto-merged.
	base := "services:\n  web:\n    image: nginx:latest\n"
	override := "services:\n  web:\n    image: nginx:1.27\n"
	got := parseCompose(t, "compose.prod.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{"services":{"web":{"image":"nginx:latest"}}}`, got[0])
}

func TestParse_ExtendsResolvedBeforeOverrideMerge(t *testing.T) {
	// Per Compose (compose-go), each file's extends is resolved before files
	// are merged: web inherits the base file's privileged:true when its extends
	// resolves, and the override's later change to `base` does not retroactively
	// affect the already-resolved web (matches docker compose config).
	base := `
services:
  base:
    image: nginx:1.27
    privileged: true
  web:
    extends: base
`
	override := `
services:
  base:
    privileged: false
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "base": {"image": "nginx:1.27", "privileged": false},
	    "web": {"image": "nginx:1.27", "privileged": true}
	  }
	}`, got[0])
}

func TestParse_OverrideExtendsResolveWithinOverrideFile(t *testing.T) {
	// The override file's own extends resolves against the override file's
	// own services before merging (compose-go resolves extends per file); the
	// base file's `base` service is not a same-file target for it.
	base := `
services:
  base:
    image: nginx:1.27
  web:
    image: alpine:3.20
`
	override := `
services:
  web:
    extends: local
  local:
    image: nginx:1.28
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "base": {"image": "nginx:1.27"},
	    "web": {"image": "nginx:1.28"},
	    "local": {"image": "nginx:1.28"}
	  }
	}`, got[0])
}

func TestParse_OverrideNotMergedAcrossVariants(t *testing.T) {
	// Compose pairs each default base name with its own override variant:
	// compose.yaml never auto-merges docker-compose.override.yaml.
	base := "services:\n  web:\n    image: nginx:latest\n"
	crossVariantOverride := "services:\n  web:\n    image: nginx:1.27\n"
	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"docker-compose.override.yaml": crossVariantOverride,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{"services":{"web":{"image":"nginx:latest"}}}`, got[0])
}

func TestParse_ExtendsSameFile(t *testing.T) {
	compose := `
services:
  common:
    image: alpine:3.20
    privileged: true
    environment:
      - LOG_LEVEL=info
  web:
    extends: common
    privileged: false
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "common": {
	      "image": "alpine:3.20",
	      "privileged": true,
	      "environment": ["LOG_LEVEL=info"]
	    },
	    "web": {
	      "image": "alpine:3.20",
	      "environment": ["LOG_LEVEL=info"],
	      "privileged": false
	    }
	  }
	}`, got[0], "inherits target config, own settings win, extends key removed")
}

func TestParse_ExtendsCycle(t *testing.T) {
	compose := `
services:
  a:
    extends: b
    image: alpine:3.20
  b:
    extends: a
    privileged: true
`
	// Must not hang; both services remain parseable.
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.NotEmpty(t, got)
}

func TestParse_ExtendsCrossFileWithLongSyntax(t *testing.T) {
	base := `
services:
  web:
    extends:
      service: common
      file: ./common.yaml
    privileged: false
`
	common := `
services:
  common:
    image: alpine:3.20
    privileged: true
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{"common.yaml": common})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "image": "alpine:3.20",
	      "privileged": false
	    }
	  }
	}`, got[0])
}

func TestParse_ExtendsMergesSequenceFields(t *testing.T) {
	// The extends merge policy unions cap_add/security_opt (dedup) and dns
	// (no dedup) per the Compose Specification, instead of replacing them like
	// the file merge does.
	compose := `
services:
  common:
    image: alpine:3.20
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    dns:
      - 1.1.1.1
  web:
    extends: common
    cap_add:
      - NET_ADMIN
      - SYS_TIME
    security_opt:
      - seccomp:unconfined
    dns:
      - 1.1.1.1
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "common": {
	      "image": "alpine:3.20",
	      "cap_add": ["NET_ADMIN"],
	      "security_opt": ["no-new-privileges:true"],
	      "dns": ["1.1.1.1"]
	    },
	    "web": {
	      "image": "alpine:3.20",
	      "cap_add": ["NET_ADMIN", "SYS_TIME"],
	      "security_opt": ["no-new-privileges:true", "seccomp:unconfined"],
	      "dns": ["1.1.1.1", "1.1.1.1"]
	    }
	  }
	}`, got[0])
}

func TestParse_ExtendsMergesEnvironmentEntriesByKey(t *testing.T) {
	// environment in list syntax is merged by key with the extending
	// service's entries winning; a bare entry shadows the referenced
	// service's same-key entry.
	compose := `
services:
  common:
    image: alpine:3.20
    environment:
      - LOG_LEVEL=info
      - DB_PASSWORD=hunter2
      - PORT=8080
  web:
    extends: common
    environment:
      - LOG_LEVEL=debug
      - DB_PASSWORD
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "common": {
	      "image": "alpine:3.20",
	      "environment": ["LOG_LEVEL=info", "DB_PASSWORD=hunter2", "PORT=8080"]
	    },
	    "web": {
	      "image": "alpine:3.20",
	      "environment": ["PORT=8080", "LOG_LEVEL=debug", "DB_PASSWORD"]
	    }
	  }
	}`, got[0])
}

func TestParse_ExtendsFileInterpolated(t *testing.T) {
	// extends.file and env_file paths are interpolated from the .env file
	// before sibling resolution.
	compose := `
services:
  web:
    extends:
      service: common
      file: ${COMMON_FILE}
    env_file: ${ENV_FILE}
`
	common := `
services:
  common:
    image: alpine:3.20
`
	got := parseCompose(t, "compose.yaml", compose, map[string]string{
		"common.yaml": common,
		"app.env":     "SECRET_TOKEN=hunter2\n",
		".env":        "COMMON_FILE=common.yaml\nENV_FILE=app.env\n",
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "image": "alpine:3.20",
	      "env_file": "app.env",
	      "environment": ["SECRET_TOKEN=hunter2"]
	    }
	  }
	}`, got[0])
}

func TestParse_EnvFileListSyntax(t *testing.T) {
	compose := `
services:
  web:
    image: nginx:${TAG:-latest}
    env_file:
      - app.env
      - path: extra.env
        required: false
    environment:
      - LOG_LEVEL=debug
      - TAG
`
	got := parseCompose(t, "compose.yaml", compose, map[string]string{
		".env":      "TAG=1.27\n",
		"app.env":   "DB_PASSWORD=hunter2\nLOG_LEVEL=warn\n",
		"extra.env": "EXTRA=x\n",
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "image": "nginx:1.27",
	      "env_file": ["app.env", {"path": "extra.env", "required": false}],
	      "environment": [
	        "LOG_LEVEL=debug",
	        "TAG=1.27",
	        "DB_PASSWORD=hunter2",
	        "EXTRA=x"
	      ]
	    }
	  }
	}`, got[0], "explicit entries win, bare KEY filled from .env, missing env_file keys appended")
}

func TestParse_EnvFileMappingEnvironment(t *testing.T) {
	compose := `
services:
  web:
    image: nginx:1.27
    env_file: app.env
    environment:
      LOG_LEVEL: debug
      OPT:
`
	got := parseCompose(t, "compose.yaml", compose, map[string]string{
		"app.env": "LOG_LEVEL=warn\nOPT=yes\nSECRET_TOKEN=hunter2\n",
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "image": "nginx:1.27",
	      "env_file": "app.env",
	      "environment": {
	        "LOG_LEVEL": "debug",
	        "OPT": "yes",
	        "SECRET_TOKEN": "hunter2"
	      }
	    }
	  }
	}`, got[0], "mapping entries win, null values filled, new keys appended")
}

func TestParse_OverrideMerge_LineAttributionKeepsBaseLine(t *testing.T) {
	dir := t.TempDir()
	// The override declares its image further down than the base file does,
	// so the test fails if the merged node keeps the override's own position
	// (in the previous layout both happened to sit on line 3).
	base := "services:\n  web:\n    image: nginx:latest\n"
	override := "services:\n  web:\n    # keep lines distinct from the base file\n    image: nginx:1.27\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(base), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.override.yaml"), []byte(override), 0o600))

	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(base), filepath.Join(dir, "compose.yaml"), true, 15)
	require.NoError(t, err)
	web := asMap(asMap(docs[0]["services"])["web"])
	require.Equal(t, "nginx:1.27", web["image"])
	lineObj := web["_dd_lines"].(map[string]*model.LineObject)["_dd_image"]
	require.Equal(t, 3, lineObj.Line, "overridden value must keep the base file's declaration line")
}

func TestParse_OverrideMerge_AppendedKeyLinesStayInBaseFile(t *testing.T) {
	dir := t.TempDir()
	// The override only adds keys: `privileged` under the existing `web`
	// service and a whole new `api` service. Their own positions would be
	// coordinates in the override file; the merged document must not carry
	// them, or findings would point at lines that mean something else (or
	// nothing) in the base file.
	base := "services:\n  web:\n    image: nginx:latest\n"
	override := "services:\n  web:\n    privileged: false\n  api:\n    image: alpine:3.20\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(base), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.override.yaml"), []byte(override), 0o600))

	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(base), filepath.Join(dir, "compose.yaml"), true, 15)
	require.NoError(t, err)
	baseLineCount := len(strings.Split(base, "\n"))

	web := asMap(asMap(docs[0]["services"])["web"])
	require.Equal(t, false, web["privileged"])
	for key, lineObj := range web["_dd_lines"].(map[string]*model.LineObject) {
		require.Greaterf(t, lineObj.Line, 0, "web.%s", key)
		require.LessOrEqualf(t, lineObj.Line, baseLineCount, "web.%s must point into the base file", key)
	}

	api := asMap(asMap(docs[0]["services"])["api"])
	require.Equal(t, "alpine:3.20", api["image"])
	for key, lineObj := range api["_dd_lines"].(map[string]*model.LineObject) {
		require.Greaterf(t, lineObj.Line, 0, "api.%s", key)
		require.LessOrEqualf(t, lineObj.Line, baseLineCount, "api.%s must point into the base file", key)
	}
}

func TestParse_ExtendsCrossFile_InheritedValuesUseExtendsLine(t *testing.T) {
	dir := t.TempDir()
	// `image` is inherited from a sibling file, where it sits on line 3. The
	// merged document is reported against the base file, which is shorter,
	// so the inherited value must be attributed to the extends declaration's
	// line instead of the sibling's coordinates.
	base := "services:\n  web:\n    extends:\n      service: common\n      file: ./common.yaml\n    privileged: false\n"
	common := "services:\n  common:\n    image: alpine:3.20\n    privileged: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(base), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "common.yaml"), []byte(common), 0o600))

	p := NewDefaultWithFS(nil)
	_, docs, _, _, err := p.Parse(context.Background(), []byte(base), filepath.Join(dir, "compose.yaml"), true, 15)
	require.NoError(t, err)
	web := asMap(asMap(docs[0]["services"])["web"])
	require.Equal(t, "alpine:3.20", web["image"])
	lineObj := web["_dd_lines"].(map[string]*model.LineObject)["_dd_image"]
	require.Equal(t, 4, lineObj.Line, "inherited value must be attributed to the extends declaration's line")
	baseLineCount := len(strings.Split(base, "\n"))
	for key, lineObj := range web["_dd_lines"].(map[string]*model.LineObject) {
		require.LessOrEqualf(t, lineObj.Line, baseLineCount, "web.%s must point into the base file", key)
	}
}

func TestParse_ExtendsCrossFile_NestedSameFileChain(t *testing.T) {
	// The sibling file's `web` extends a service from the sibling's own
	// services mapping (`common`), while the base file also has a `common`
	// with a different image. The chain must resolve against the sibling's
	// mapping, not the base file's, or `web` would inherit nginx:latest.
	base := `
services:
  web:
    extends:
      service: web
      file: ./common.yaml
  common:
    image: nginx:latest
`
	common := `
services:
  web:
    extends: common
  common:
    image: alpine:3.20
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{"common.yaml": common})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {"image": "alpine:3.20"},
	    "common": {"image": "nginx:latest"}
	  }
	}`, got[0])
}

func TestParse_OverrideMerge_LongSyntaxPortsDeduplicated(t *testing.T) {
	// ports is a merged (union) list, and long-syntax entries are mappings:
	// an override repeating the base's entry must not duplicate it.
	base := `
services:
  web:
    ports:
      - target: 80
        published: 8080
`
	override := `
services:
  web:
    ports:
      - target: 80
        published: 8080
      - target: 443
        published: 8443
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "ports": [
	        {"target": 80, "published": 8080},
	        {"target": 443, "published": 8443}
	      ]
	    }
	  }
	}`, got[0])
}

func TestParse_EnvFileMissingOptional(t *testing.T) {
	compose := `
services:
  web:
    image: nginx:1.27
    env_file:
      - path: missing.env
        required: false
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	require.JSONEq(t, `{"services":{"web":{"image":"nginx:1.27","env_file":[{"path":"missing.env","required":false}]}}}`, got[0])
}

func TestParse_EnvFileMissingOptional_CapitalFalse(t *testing.T) {
	// YAML 1.1 allows "False" as a boolean; an unquoted capital-F false must
	// still make the env_file optional, while a quoted "false" is a string
	// (rejected by Compose) and must stay required.
	compose := `
services:
  web:
    image: nginx:1.27
    env_file:
      - path: missing.env
        required: False
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	require.JSONEq(t, `{"services":{"web":{"image":"nginx:1.27","env_file":[{"path":"missing.env","required":false}]}}}`, got[0])
}

func TestIsOverrideFileName(t *testing.T) {
	require.True(t, names.IsOverrideFileName("compose.override.yaml"))
	require.True(t, names.IsOverrideFileName("/a/b/docker-compose.override.yml"))
	require.False(t, names.IsOverrideFileName("compose.yaml"))
	require.False(t, names.IsOverrideFileName("compose.prod.yaml"))
	require.False(t, names.IsOverrideFileName("compose.override.extra.yaml"))
	require.True(t, names.IsDefaultBaseFileName("compose.yml"))
	require.True(t, names.IsDefaultBaseFileName("docker-compose.yaml"))
	require.False(t, names.IsDefaultBaseFileName("compose.prod.yaml"))
	require.False(t, names.IsDefaultBaseFileName("compose.override.yaml"))
}

// TestNewDefaultWithFS_MemFS verifies sibling reads (.env, env_file, extends
// file, override) work against the in-memory FS used by the HTTP server.
func TestNewDefaultWithFS_MemFS(t *testing.T) {
	mem := vfs.NewMemFS(map[string][]byte{
		"compose.yaml": []byte("services:\n  web:\n    image: nginx:${TAG:-latest}\n"),
		".env":         []byte("TAG=1.27\n"),
	})

	p := NewDefaultWithFS(mem)
	_, docs, _, _, err := p.Parse(context.Background(), []byte("services:\n  web:\n    image: nginx:${TAG:-latest}\n"), "compose.yaml", true, 15)
	require.NoError(t, err)
	web := asMap(asMap(docs[0]["services"])["web"])
	require.Equal(t, "nginx:1.27", web["image"])
}

func TestParse_CyclicAliasSelfReference(t *testing.T) {
	// A self-referential anchor parses into a cyclic node tree (the back-edge
	// runs through the alias node's .Alias pointer); the cycle breaker cuts the
	// back-edge to a null, and extending the service must not recurse forever.
	compose := `
services:
  common: &base
    image: alpine
    self: *base
  web:
    extends: common
`
	require.NotPanics(t, func() {
		got := parseCompose(t, "compose.yaml", compose, nil)
		require.Len(t, got, 1)
		require.JSONEq(t, `{"services":{"common":{"image":"alpine","self":null},"web":{"image":"alpine","self":null}}}`, got[0])
	})
}

func TestParse_CyclicAliasInterpolation(t *testing.T) {
	// The semantic path runs even without extends (a `$` triggers it), so the
	// cycle must be cut before interpolation walks the document.
	compose := `
services:
  common: &base
    image: alpine:${TAG}
    self: *base
`
	require.NotPanics(t, func() {
		got := parseCompose(t, "compose.yaml", compose, nil)
		require.Len(t, got, 1)
		require.JSONEq(t, `{"services":{"common":{"image":"alpine:${TAG}","self":null}}}`, got[0])
	})
}

func TestParse_AliasReuseIsNotACycle(t *testing.T) {
	// Two references to the same anchor are sharing, not a cycle: the cycle
	// breaker must leave them intact and copyNode must copy both.
	compose := `
x-opts: &opts
  log_level: info
  verbose: true
services:
  common:
    image: alpine
    first: *opts
    second: *opts
  web:
    extends: common
`
	got := parseCompose(t, "compose.yaml", compose, nil)
	require.Len(t, got, 1)
	// The model flattens alias-to-mapping values into their parent (pre-existing
	// behavior, identical to the plain YAML path); what matters here is that
	// the shared anchor's content survives the cycle breaker and copyNode into
	// the extending service.
	require.JSONEq(t, `{
	  "services": {
	    "common": {"image": "alpine", "log_level": "info", "verbose": true},
	    "web": {"image": "alpine", "log_level": "info", "verbose": true}
	  },
	  "x-opts": {"log_level": "info", "verbose": true}
	}`, got[0])
}

func TestBreakAliasCycles_CutsAliasBackEdge(t *testing.T) {
	// yaml.v3 alias nodes carry no Content — the cycle runs through the .Alias
	// pointer — so the cycle breaker must follow alias targets to see (and cut)
	// a self-referential anchor.
	var doc yaml.Node
	src := "a: &x\n  b: *x\n"
	require.NoError(t, yaml.Unmarshal([]byte(src), &doc))
	root := doc.Content[0]
	breakAliasCycles(root)

	val := root.Content[1] // mapping value of "a"
	require.Equal(t, yaml.MappingNode, val.Kind)
	self := val.Content[1] // value of "b"
	require.Equal(t, yaml.ScalarNode, self.Kind, "the cyclic alias must be replaced with a null scalar")
	require.Equal(t, "!!null", self.Tag)
	require.Nil(t, self.Alias)
}

func TestBreakAliasCycles_KeepsPlainAliases(t *testing.T) {
	var doc yaml.Node
	src := "opts: &o {k: v}\nservices:\n  a: *o\n"
	require.NoError(t, yaml.Unmarshal([]byte(src), &doc))
	root := doc.Content[0]
	breakAliasCycles(root)

	svc := root.Content[3] // services value
	alias := svc.Content[1]
	require.Equal(t, yaml.AliasNode, alias.Kind, "a non-cyclic alias must survive")
	require.NotNil(t, alias.Alias)
}

func TestParse_MultipleExtendsSameSiblingFile(t *testing.T) {
	// Several services extending the same sibling file must all resolve
	// against its (cached) root, each getting an independent copy.
	base := `
services:
  one:
    extends:
      file: ./common.yaml
      service: shared
  two:
    extends:
      file: ./common.yaml
      service: shared
    image: alpine:3.20
`
	common := `
services:
  shared:
    image: nginx:1.27
    privileged: true
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{"common.yaml": common})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "one": {"image": "nginx:1.27", "privileged": true},
	    "two": {"image": "alpine:3.20", "privileged": true}
	  }
	}`, got[0])
}

func TestOverrideNameFor(t *testing.T) {
	require.Equal(t, "compose.override.yaml", names.OverrideNameFor("compose.yaml"))
	require.Equal(t, "compose.override.yml", names.OverrideNameFor("compose.yml"))
	require.Equal(t, "docker-compose.override.yaml", names.OverrideNameFor("docker-compose.yaml"))
	require.Equal(t, "docker-compose.override.yml", names.OverrideNameFor("docker-compose.yml"))
	require.Equal(t, "compose.override.yaml", names.OverrideNameFor("/a/b/Compose.YAML"),
		"pairing follows the default base name matching")
	require.Equal(t, "", names.OverrideNameFor("compose.prod.yaml"))
	require.Equal(t, "", names.OverrideNameFor("compose.override.yaml"))
}

func TestParse_OverrideMergeUnionsServiceSequences(t *testing.T) {
	// Per the Compose merge rules (compose-go override/merge), file merge
	// appends sequences — security_opt, cap_add, etc. keep the base file's
	// entries — instead of replacing them; only command, entrypoint and
	// healthcheck.test are overridden.
	base := `
services:
  web:
    security_opt:
      - seccomp=unconfined
    cap_add:
      - NET_ADMIN
    command:
      - sh
      - -c
      - echo base
    ports:
      - "8080:80"
`
	override := `
services:
  web:
    security_opt:
      - no-new-privileges:true
    cap_add:
      - SYS_PTRACE
    command:
      - sh
      - -c
      - echo override
    ports:
      - "8443:443"
`
	got := parseCompose(t, "compose.yaml", base, map[string]string{
		"compose.override.yaml": override,
	})
	require.Len(t, got, 1)
	require.JSONEq(t, `{
	  "services": {
	    "web": {
	      "security_opt": ["seccomp=unconfined", "no-new-privileges:true"],
	      "cap_add": ["NET_ADMIN", "SYS_PTRACE"],
	      "command": ["sh", "-c", "echo override"],
	      "ports": ["8080:80", "8443:443"]
	    }
	  }
	}`, got[0])
}

func TestParse_DeepExtendsChainResolvesFully(t *testing.T) {
	// Compose (compose-go) imposes no extends depth limit, only cycle
	// detection: a legitimate chain longer than any fixed cap must resolve
	// completely, or settings inherited from the chain head silently
	// disappear from the merged document.
	depth := 15
	var sb strings.Builder
	sb.WriteString("services:\n  svc0:\n    image: nginx:1.27\n    privileged: true\n")
	for i := 1; i <= depth; i++ {
		sb.WriteString(fmt.Sprintf("  svc%d:\n    extends: svc%d\n", i, i-1))
	}
	got := parseCompose(t, "compose.yaml", sb.String(), nil)
	require.Len(t, got, 1)
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(got[0]), &doc))
	last := fmt.Sprintf("svc%d", depth)
	web := asMap(asMap(doc["services"])[last])
	require.Equal(t, "nginx:1.27", web["image"], "the full chain must resolve")
	require.Equal(t, true, web["privileged"], "deep inheritance must not be truncated")
}

func TestCopyNode_MemoizesSharedAnchors(t *testing.T) {
	// Stacked anchor reuse (a block referenced k times per level over d
	// levels) used to cost k^d physical node copies in copyNode — the shape
	// measured at 19 GB before being killed. The memo copies each shared
	// anchor block once, so this exact shape must copy in linear time.
	levels, refs := 9, 6
	var sb strings.Builder
	sb.WriteString("x-l0: &l0\n  image: alpine\n")
	for l := 1; l <= levels; l++ {
		sb.WriteString(fmt.Sprintf("x-l%d: &l%d\n", l, l))
		for r := 0; r < refs; r++ {
			sb.WriteString(fmt.Sprintf("  f%d: *l%d\n", r, l-1))
		}
	}
	sb.WriteString("services:\n  base:\n")
	for r := 0; r < refs; r++ {
		sb.WriteString(fmt.Sprintf("    k%d: *l%d\n", r, levels))
	}
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(sb.String()), &doc))
	base := serviceNode(doc.Content[0], "base")
	require.NotNil(t, base)

	done := make(chan *yaml.Node)
	go func() {
		done <- copyNode(base)
	}()
	var copied *yaml.Node
	select {
	case copied = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("copyNode did not complete in 5s: shared-anchor memoization regressed")
	}
	// The copy preserves the anchor content and shares it across references:
	// every k alias resolves to the same copied subtree.
	require.Equal(t, yaml.AliasNode, copied.Content[1].Kind)
	require.Equal(t, copied.Content[1].Alias, copied.Content[3].Alias,
		"two references to the same anchor must share one copied subtree")
	require.Equal(t, "l9", copied.Content[1].Alias.Anchor,
		"the shared copy keeps the anchor's identity")
}
