/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package terragrunt

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	tfmodules "github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/modules"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

const (
	paramArgs    = "args"
	paramName    = "name"
	paramDefault = "default"
	paramPath    = "path"
	paramValue   = "value"
)

// unknownFunctions only have a value when Terragrunt runs: they execute
// commands, call cloud APIs, decrypt secrets or read the host.
var unknownFunctions = []string{
	"run_cmd",
	"sops_decrypt_file",
	"get_aws_account_id",
	"get_aws_account_alias",
	"get_aws_caller_identity_arn",
	"get_aws_caller_identity_user_id",
	"get_platform",
	"get_working_dir",
}

// commandLists are Terragrunt's lists of Terraform commands, space separated.
var commandLists = map[string]string{
	"get_terraform_commands_that_need_vars":        "apply console destroy import plan push refresh",
	"get_terraform_commands_that_need_locking":     "apply destroy import init plan refresh taint untaint",
	"get_terraform_commands_that_need_input":       "apply import init plan refresh",
	"get_terraform_commands_that_need_parallelism": "apply plan destroy",
}

// functions is the Terraform function table plus Terragrunt's, answering for
// scope s. File functions resolve from the directory of s.configPath and stay
// inside the repository.
func (t *translator) functions(s *scope) map[string]function.Function {
	dir := filepath.Dir(s.configPath)
	funcs := functions.EvalFuncsWithRoot(dir, t.root, t.fsys)

	for _, name := range unknownFunctions {
		funcs[name] = unknownFunc
	}
	for name, list := range commandLists {
		funcs[name] = constFunc(stringList(strings.Fields(list)))
	}
	funcs["get_default_retryable_errors"] = constFunc(cty.ListValEmpty(cty.String))
	funcs["get_terraform_command"] = constFunc(cty.StringVal("plan"))
	funcs["get_terraform_cli_args"] = constFunc(cty.ListValEmpty(cty.String))
	funcs["get_env"] = getEnvFunc
	funcs["mark_as_read"] = identityFunc
	funcs["mark_glob_as_read"] = identityFunc

	funcs["get_terragrunt_dir"] = constFunc(cty.StringVal(dir))
	funcs["get_original_terragrunt_dir"] = constFunc(cty.StringVal(filepath.Dir(s.originalPath)))
	funcs["get_repo_root"] = constFunc(cty.StringVal(t.root))
	funcs["get_path_from_repo_root"] = constFunc(cty.StringVal(relSlash(t.root, dir)))
	funcs["get_path_to_repo_root"] = constFunc(cty.StringVal(relSlash(dir, t.root)))
	funcs["get_parent_terragrunt_dir"] = includeFunc(s, func(parent string) string { return parent }, dir)
	funcs["path_relative_to_include"] = includeFunc(s, func(parent string) string { return relSlash(parent, dir) }, ".")
	funcs["path_relative_from_include"] = includeFunc(s, func(parent string) string { return relSlash(dir, parent) }, ".")
	funcs["find_in_parent_folders"] = t.findInParentFoldersFunc(dir)
	funcs["read_terragrunt_config"] = t.readTerragruntConfigFunc(s, dir)
	funcs["read_tfvars_file"] = t.readTfvarsFileFunc(dir)
	return funcs
}

var unknownFunc = function.New(&function.Spec{
	VarParam: &function.Parameter{
		Name: paramArgs, Type: cty.DynamicPseudoType,
		AllowNull: true, AllowUnknown: true, AllowDynamicType: true, AllowMarked: true,
	},
	Type: function.StaticReturnType(cty.DynamicPseudoType),
	Impl: func([]cty.Value, cty.Type) (cty.Value, error) { return cty.DynamicVal, nil },
})

// getEnvFunc returns the default argument, never the environment: findings
// must not depend on where the scan runs.
var getEnvFunc = function.New(&function.Spec{
	Params:   []function.Parameter{{Name: paramName, Type: cty.String, AllowUnknown: true}},
	VarParam: &function.Parameter{Name: paramDefault, Type: cty.String, AllowNull: true, AllowUnknown: true},
	Type:     function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		if len(args) > 1 {
			return args[1], nil
		}
		return cty.UnknownVal(cty.String), nil
	},
})

var identityFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: paramValue, Type: cty.DynamicPseudoType, AllowNull: true, AllowUnknown: true}},
	Type:   func(args []cty.Value) (cty.Type, error) { return args[0].Type(), nil },
	Impl:   func(args []cty.Value, _ cty.Type) (cty.Value, error) { return args[0], nil },
})

// constFunc ignores its arguments, if any, and returns value.
func constFunc(value cty.Value) function.Function {
	return function.New(&function.Spec{
		VarParam: &function.Parameter{
			Name: paramArgs, Type: cty.DynamicPseudoType,
			AllowNull: true, AllowUnknown: true, AllowDynamicType: true,
		},
		Type: function.StaticReturnType(value.Type()),
		Impl: func([]cty.Value, cty.Type) (cty.Value, error) { return value, nil },
	})
}

func stringList(values []string) cty.Value {
	out := make([]cty.Value, len(values))
	for i, v := range values {
		out[i] = cty.StringVal(v)
	}
	return cty.ListVal(out)
}

// includeFunc answers for the include named by its optional argument, or the
// first include, with fallback when the file includes nothing.
func includeFunc(s *scope, answer func(parentDir string) string, fallback string) function.Function {
	return function.New(&function.Spec{
		VarParam: &function.Parameter{Name: paramName, Type: cty.String},
		Type:     function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			path, ok := s.include(args)
			if !ok {
				return cty.StringVal(fallback), nil
			}
			return cty.StringVal(answer(filepath.Dir(path))), nil
		},
	})
}

func (s *scope) include(args []cty.Value) (string, bool) {
	if len(args) > 0 {
		path, ok := s.includes[args[0].AsString()]
		return path, ok
	}
	if len(s.includeOrder) == 0 {
		return "", false
	}
	return s.includes[s.includeOrder[0]], true
}

// findInParentFoldersFunc searches the directories above dir, up to the
// repository root and never beyond, for a file (terragrunt.hcl by default).
func (t *translator) findInParentFoldersFunc(dir string) function.Function {
	return function.New(&function.Spec{
		VarParam: &function.Parameter{Name: paramArgs, Type: cty.String},
		Type:     function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			name := tfpath.TerragruntUnit
			if len(args) > 0 {
				name = args[0].AsString()
			}
			if found, ok := t.findInParentFolders(dir, name); ok {
				return cty.StringVal(found), nil
			}
			if len(args) > 1 {
				return args[1], nil
			}
			return cty.NilVal, fmt.Errorf("could not find %s in a folder above %s", name, dir)
		},
	})
}

func (t *translator) findInParentFolders(dir, name string) (string, bool) {
	for current := filepath.Dir(dir); t.inRoot(current); current = filepath.Dir(current) {
		candidate := filepath.Join(current, name)
		// As in Terragrunt, any existing path matches, directories included.
		if _, err := t.fsys.Stat(candidate); err == nil {
			if confined, err := functions.ConfinePath(t.root, t.fsys, candidate); err == nil {
				return confined, true
			}
		}
		if current == t.root || filepath.Dir(current) == current {
			break
		}
	}
	return "", false
}

func (t *translator) inRoot(path string) bool {
	rel, err := filepath.Rel(t.root, path)
	return err == nil && rel != parentDir && !strings.HasPrefix(rel, parentDir+string(filepath.Separator))
}

// readTerragruntConfigFunc evaluates another config as its own unit, so its
// path functions describe it; get_original_terragrunt_dir still describes the
// unit being translated. A failure returns the default argument when given.
func (t *translator) readTerragruntConfigFunc(s *scope, dir string) function.Function {
	return function.New(&function.Spec{
		Params:   []function.Parameter{{Name: paramPath, Type: cty.String}},
		VarParam: &function.Parameter{Name: paramDefault, Type: cty.DynamicPseudoType, AllowNull: true},
		Type:     function.StaticReturnType(cty.DynamicPseudoType),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			value, err := t.readTerragruntConfig(s, dir, args[0].AsString())
			if err != nil && len(args) > 1 {
				return args[1], nil
			}
			return value, err
		},
	})
}

func (t *translator) readTerragruntConfig(s *scope, dir, target string) (cty.Value, error) {
	path, err := t.confine(dir, target)
	if err != nil {
		return cty.NilVal, err
	}
	if s.depth >= maxReadDepth {
		return cty.NilVal, errors.New("read_terragrunt_config is nested too deep")
	}
	if s.reading[path] {
		return cty.NilVal, fmt.Errorf("read_terragrunt_config cycle through %s", path)
	}
	if v, ok := t.reads[path]; ok {
		return v, nil
	}
	body, err := t.parseFile(path)
	if err != nil {
		return cty.NilVal, err
	}
	s.reading[path] = true
	defer delete(s.reading, path)
	child := &scope{configPath: path, originalPath: s.originalPath, depth: s.depth + 1, reading: s.reading}
	cfg, err := t.evalFile(path, body, child, true)
	if err != nil {
		return cty.NilVal, err
	}
	value := cfg.object()
	t.reads[path] = value
	return value, nil
}

// readTfvarsFileFunc returns a tfvars file's values as JSON text, as
// Terragrunt does.
func (t *translator) readTfvarsFileFunc(dir string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: paramPath, Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
			path, err := t.confine(dir, args[0].AsString())
			if err != nil {
				return cty.NilVal, err
			}
			value, err := t.parseTfvars(path)
			if err != nil {
				return cty.NilVal, err
			}
			out, err := ctyjson.Marshal(value, value.Type())
			if err != nil {
				return cty.NilVal, err
			}
			return cty.StringVal(string(out)), nil
		},
	})
}

func (t *translator) parseTfvars(path string) (cty.Value, error) {
	src, err := tfmodules.ReadConfigFile(t.ctx, t.fsys, path, "")
	if err != nil {
		return cty.NilVal, err
	}
	if strings.HasSuffix(path, ".json") {
		ty, err := ctyjson.ImpliedType(src)
		if err != nil {
			return cty.NilVal, err
		}
		return ctyjson.Unmarshal(src, ty)
	}
	attrs := tfmodules.ParseVarsFile(src, path)
	if attrs == nil {
		return cty.NilVal, fmt.Errorf("%s is not a valid variable definitions file", path)
	}
	values := make(map[string]cty.Value, len(attrs))
	for name, a := range attrs {
		value, diags := a.Expr.Value(nil)
		if diags.HasErrors() {
			return cty.NilVal, diags
		}
		values[name] = value
	}
	return cty.ObjectVal(values), nil
}

func relSlash(from, to string) string {
	rel, err := filepath.Rel(from, to)
	if err != nil {
		return to
	}
	return filepath.ToSlash(rel)
}
