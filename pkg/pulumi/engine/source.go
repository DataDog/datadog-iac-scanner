/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
)

// sourceOf converts the SDK's source position. The path is made relative to
// the scan root; a position outside the root keeps only its URI: some Go
// provider SDKs report a frame inside their own generated code (in the module
// cache), which is not the user's constructor call.
func (s *Server) sourceOf(sp *pulumirpc.SourcePosition) *capture.Source {
	if sp == nil || sp.GetUri() == "" {
		return nil
	}
	src := &capture.Source{URI: sp.GetUri()}
	abs := s.absolutePath(sp.GetUri())
	if abs == "" {
		return src
	}
	rel, ok := s.underRoot(abs)
	if !ok {
		return src
	}
	src.Path = rel
	src.Line = int(sp.GetLine())
	src.Column = int(sp.GetColumn())
	return src
}

// underRoot returns abs relative to the scan root, trying the root as given and
// with symbolic links resolved, since SDKs may report either form.
func (s *Server) underRoot(abs string) (string, bool) {
	candidates := []string{abs}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && resolved != abs {
		candidates = append(candidates, resolved)
	}
	for _, root := range s.roots {
		for _, p := range candidates {
			rel, err := filepath.Rel(root, p)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				continue
			}
			return filepath.ToSlash(rel), true
		}
	}
	return "", false
}

// fileURIPath returns the local path, with forward slashes, of a file: URI
// with the given host and path, or "" when the URI names another host. On
// Windows, the drive letter comes either in the host (file://C:/x) or at the
// start of the path (file:///C:/x).
func fileURIPath(host, path string, windows bool) string {
	switch {
	case windows && isDriveLetter(host):
		return host + path
	case host != "" && host != "localhost":
		return ""
	case windows && len(path) >= 3 && path[0] == '/' && isDriveLetter(path[1:3]):
		return path[1:]
	}
	return path
}

// isDriveLetter reports whether s is a Windows drive such as "C:".
func isDriveLetter(s string) bool {
	return len(s) == 2 && s[1] == ':' && ('a' <= s[0] && s[0] <= 'z' || 'A' <= s[0] && s[0] <= 'Z')
}

// absolutePath returns the local path of a source URI, or "" if it has none.
func (s *Server) absolutePath(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "file":
		p := fileURIPath(u.Host, u.Path, runtime.GOOS == "windows")
		if p == "" {
			return ""
		}
		return filepath.Clean(filepath.FromSlash(p))
	case "project": // relative to the project directory
		if s.opts.ProjectDir == "" {
			return ""
		}
		return filepath.Join(s.opts.ProjectDir, filepath.FromSlash(strings.TrimPrefix(u.Host+u.Path, "/")))
	case "":
		if filepath.IsAbs(uri) {
			return filepath.Clean(uri)
		}
	}
	return ""
}
