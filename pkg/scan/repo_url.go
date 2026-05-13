/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package scan

import (
	"errors"
	"os"
	"path/filepath"

	git "github.com/go-git/go-git/v5"
)

// lookupRepositoryURL returns the URL of the `origin` remote of the git repository
// containing rootPath, or the empty string when no enclosing repository or remote
// is found.
func lookupRepositoryURL(rootPath string) string {
	repo, err := openRepoFrom(rootPath)
	if err != nil {
		return ""
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return ""
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

// openRepoFrom opens the git repository containing rootPath, walking up parent
// directories until one is found.
func openRepoFrom(rootPath string) (*git.Repository, error) {
	dir, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	for {
		if stat, statErr := os.Stat(dir); statErr == nil && stat.IsDir() {
			if repo, openErr := git.PlainOpen(dir); openErr == nil {
				return repo, nil
			} else if !errors.Is(openErr, git.ErrRepositoryNotExists) {
				return nil, openErr
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "" || parent == "." {
			return nil, git.ErrRepositoryNotExists
		}
		dir = parent
	}
}
