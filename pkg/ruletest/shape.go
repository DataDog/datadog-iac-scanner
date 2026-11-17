package ruletest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// blockIDField marks a result of the Terraform rule contract: the engine
// derives the document, resource and search key from the block it names.
const blockIDField = "_dd_id"

// legacyRequiredFields are required in every result that does not name a block.
var legacyRequiredFields = []string{"documentId", "searchKey"}

// legacyResourceFields are required in results that do not name a block, on
// the platforms that report resources.
var legacyResourceFields = []string{"resourceType", "resourceName"}

// derivedFields are derived by the engine from the block a result names, so
// such a result must not set them.
var derivedFields = []string{"documentId", "searchKey", "resourceType", "resourceName"}

// validateResult checks one raw rule result against the result contract. The
// deprecated fields issueType, keyExpectedValue and keyActualValue are never
// required.
func validateResult(m map[string]any, platform, ruleID string, requireResourceKeys bool) []string {
	var errs []string
	if block, ok := m[blockIDField]; ok {
		errs = validateBlockResult(m, block)
	} else {
		for _, key := range legacyRequiredFields {
			if _, ok := m[key]; !ok {
				errs = append(errs, fmt.Sprintf("Result missing required field %q", key))
			}
		}
		if requireResourceKeys {
			for _, key := range legacyResourceFields {
				if _, ok := m[key]; !ok {
					errs = append(errs, fmt.Sprintf("Result missing required field %q for platform %q in rule %s",
						key, strings.ToLower(platform), ruleID))
				}
			}
		}
	}
	_, hasRemediation := m["remediation"]
	_, hasRemediationType := m["remediationType"]
	if hasRemediation != hasRemediationType {
		errs = append(errs, "Result has remediation/remediationType only on one side; both must be set together")
	}
	return errs
}

// validateBlockResult checks a result of the shape common.finding returns:
// {_dd_id, path, key?, evidence?, remediation?, remediationType?}. Whether
// the block exists in the input is checked by the engine.
func validateBlockResult(m map[string]any, block any) []string {
	var errs []string
	if s, isString := block.(string); !isString || s == "" {
		errs = append(errs, fmt.Sprintf("Result field %q must be a non-empty string", blockIDField))
	}
	if path, ok := m["path"]; !ok {
		errs = append(errs, `Result missing required field "path"`)
	} else if msg := validatePath(path); msg != "" {
		errs = append(errs, `Result field "path" `+msg)
	}
	if key, ok := m["key"]; ok {
		switch key.(type) {
		case string, json.Number, bool:
		default:
			errs = append(errs, `Result field "key" must be a string, number or boolean`)
		}
	}
	if evidence, ok := m["evidence"]; ok {
		errs = append(errs, validateEvidence(evidence)...)
	}
	for _, key := range derivedFields {
		if _, ok := m[key]; ok {
			errs = append(errs, fmt.Sprintf("Result field %q is derived from %q and must not be set", key, blockIDField))
		}
	}
	return errs
}

// validatePath returns why path is not a list of attribute names and list
// indexes, or "".
func validatePath(path any) string {
	steps, ok := path.([]any)
	if !ok {
		return "must be an array"
	}
	for _, s := range steps {
		switch s := s.(type) {
		case string:
		case json.Number:
			if i, err := s.Int64(); err != nil || i < 0 {
				return fmt.Sprintf("holds %s, not a list index", s)
			}
		default:
			return fmt.Sprintf("holds a %T, not an attribute name or list index", s)
		}
	}
	return ""
}

func validateEvidence(evidence any) []string {
	items, ok := evidence.([]any)
	if !ok {
		return []string{`Result field "evidence" must be an array of [block id, path] pairs`}
	}
	var errs []string
	for i, item := range items {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			errs = append(errs, fmt.Sprintf(`Result field "evidence" item %d must be a [block id, path] pair`, i))
			continue
		}
		if id, ok := pair[0].(string); !ok || id == "" {
			errs = append(errs, fmt.Sprintf(`Result field "evidence" item %d must start with a block id`, i))
		}
		if msg := validatePath(pair[1]); msg != "" {
			errs = append(errs, fmt.Sprintf(`Result field "evidence" item %d path %s`, i, msg))
		}
	}
	return errs
}
