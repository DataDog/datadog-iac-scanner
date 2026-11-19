package docker

import (
	"path"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
)

// BoolValue represents a boolean fact whose value may not be statically known.
type BoolValue struct {
	Known bool `json:"known"`
	Value bool `json:"value"`
}

// packageCacheMounts projects cache mount coverage onto shell call indexes.
// Package manager facts already retain the call index, so nil entries denote
// calls for which the shell parser found no package manager.
func packageCacheMounts(execution *Execution, mounts []Mount, context *Context, mountsComplete bool) []*BoolValue {
	if execution == nil || execution.Facts == nil || len(execution.Calls) == 0 {
		return nil
	}
	result := make([]*BoolValue, len(execution.Calls))
	commands := make(map[int]*shell.PackageCommand, len(execution.PackageCommands))
	for i := range execution.PackageCommands {
		command := &execution.PackageCommands[i]
		commands[command.Call] = command
	}
	var cacheMounts []*Mount
	for i := range mounts {
		if mounts[i].Kind == "cache" {
			cacheMounts = append(cacheMounts, &mounts[i])
		}
	}
	for call, command := range commands {
		if call < 0 || call >= len(result) {
			continue
		}
		if !mountsComplete {
			result[call] = &BoolValue{}
			continue
		}
		result[call] = packageCacheMountCoverage(execution, call, command, cacheMounts, context)
	}
	return result
}

func packageCacheMountCoverage(
	execution *Execution,
	call int,
	command *shell.PackageCommand,
	mounts []*Mount,
	context *Context,
) *BoolValue {
	// With no cache mount, coverage is definitively false even when the image's
	// HOME or manager cache location is unknown.
	if len(mounts) == 0 {
		return &BoolValue{Known: true}
	}
	if !command.Known || !cacheContextCertain(execution, call) {
		return &BoolValue{}
	}
	paths, pathsKnown := packageCachePaths(command, context)
	return cachePathsCoverage(paths, pathsKnown, mounts)
}

func cachePathsCoverage(paths []string, pathsKnown bool, mounts []*Mount) *BoolValue {
	coveredPaths := make(map[string]bool, len(paths))
	uncertainMount := false
	for i := range mounts {
		mount := mounts[i]
		if !mount.Target.Known || !path.IsAbs(mount.Target.Text) {
			uncertainMount = true
			continue
		}
		target := path.Clean(mount.Target.Text)
		for _, cachePath := range paths {
			if covers(target, cachePath) {
				coveredPaths[cachePath] = true
			}
		}
	}
	if len(paths) > 0 && len(coveredPaths) == len(paths) {
		return &BoolValue{Known: true, Value: true}
	}
	if !pathsKnown || len(coveredPaths) > 0 || uncertainMount {
		return &BoolValue{}
	}
	return &BoolValue{Known: true}
}

func cacheContextCertain(execution *Execution, call int) bool {
	if !execution.Complete || execution.EnvironmentMayChange || call >= len(execution.Calls) {
		return false
	}
	invocation := execution.Calls[call]
	return len(invocation.Wrappers) == 0 && !invocation.Function && !invocation.Deferred
}

func packageCachePaths(command *shell.PackageCommand, context *Context) ([]string, bool) {
	switch command.Manager {
	case "pip":
		if value, found := optionValue(command, "--cache-dir"); found {
			return resolveCachePath(value.Text, value.Known, context)
		}
		if value, found := environmentValue(context, "PIP_CACHE_DIR"); found && len(command.Options) == 0 {
			return resolveCachePath(value.Text, value.Known, context)
		}
		return nil, false
	case "yarn":
		if value, found := optionValue(command, "--cache-folder"); found {
			return resolveCachePath(value.Text, value.Known, context)
		}
		if value, found := environmentValue(context, "YARN_CACHE_FOLDER"); found && len(command.Options) == 0 {
			return resolveCachePath(value.Text, value.Known, context)
		}
		return nil, false
	case "apk":
		if value, found := optionValue(command, "--cache-dir"); found {
			return resolveCachePath(value.Text, value.Known, context)
		}
		return nil, false
	case "dnf", "microdnf", "yum":
		return nil, false
	default:
		return nil, false
	}
}

func optionValue(command *shell.PackageCommand, name string) (shell.Value, bool) {
	var value shell.Value
	found := false
	for _, option := range command.Options {
		if option.Name == name {
			value = shell.Value{Text: option.Value, Known: command.Known && len(command.Options) == 1 && option.Value != ""}
			found = true
		}
	}
	return value, found
}

func environmentValue(context *Context, name string) (shell.Value, bool) {
	if context == nil || context.EnvironmentValues == nil {
		return shell.Value{}, false
	}
	value, found := context.EnvironmentValues[name]
	return value, found
}

func resolveCachePath(text string, known bool, context *Context) ([]string, bool) {
	if !known || text == "" {
		return nil, false
	}
	if path.IsAbs(text) {
		return []string{path.Clean(text)}, true
	}
	if context == nil || !context.Workdir.Known || !path.IsAbs(context.Workdir.Text) {
		return nil, false
	}
	return []string{path.Clean(path.Join(context.Workdir.Text, text))}, true
}

// covers reports whether a cache mount target contains the manager's complete
// cache directory. A mount nested inside the cache directory is insufficient.
func covers(target, cachePath string) bool {
	target, cachePath = path.Clean(target), path.Clean(cachePath)
	return cachePath == target || strings.HasPrefix(cachePath, strings.TrimSuffix(target, "/")+"/")
}
