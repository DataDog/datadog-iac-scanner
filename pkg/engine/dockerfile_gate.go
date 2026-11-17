package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/engine/unknowngate"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// One lazy gate is reused by the roots of one rule evaluation. Query workers
// have independent states; the initialized gate is immutable.
type dockerGateState struct {
	contractChecked bool
	contractErr     error
	gate            *unknowngate.Gate
	err             error
	initialized     bool
}

func (c *Inspector) cachedDockerUnknownGate(qCtx *QueryContext, placeholder string) (*unknowngate.Gate, error) {
	if qCtx.dockerGate == nil {
		qCtx.dockerGate = &dockerGateState{}
	}
	state := qCtx.dockerGate
	if !state.initialized {
		state.gate, state.err = c.newDockerUnknownGate(&qCtx.Query.Metadata, placeholder)
		state.initialized = true
	}
	return state.gate, state.err
}

// dockerRuleInput belongs to one Inspect call. Its immutable projection is
// shared by query workers; no scan state is retained on the Inspector.
type dockerRuleInput struct {
	payload          ast.Value
	placeholder      string
	documents        map[string]ast.Value
	unknownDocuments []ast.Value
	unknownValues    map[ast.Value]bool
}

func newDockerRuleInput(payload ast.Value) (*dockerRuleInput, error) {
	raw, err := ast.ValueToInterface(payload, nil)
	if err != nil {
		return nil, err
	}
	root, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("dockerfile input must be an object")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	placeholder := "\x00dd-unknown-" + hex.EncodeToString(nonce[:])
	docs, _ := root["document"].([]interface{})
	for _, rawDoc := range docs {
		doc, ok := rawDoc.(map[string]interface{})
		if !ok {
			continue
		}
		if facts, ok := doc["_dockerfile"].(map[string]interface{}); ok {
			id, _ := doc["id"].(string)
			stampDockerNodes(facts, id+"#/_dockerfile", false)
			uncertain := taintUnknownDockerStageRelationships(facts, placeholder)
			taintUnknownDockerInheritance(facts, placeholder, uncertain)
			projectDockerUnknownContextSetters(facts, placeholder)
			projectDockerFailedInstructionFacts(facts, placeholder)
			projectDockerFailedRunMountInventories(facts, placeholder)
			projectUnknownDockerEffectiveConfig(facts, placeholder)
			taintUnknownDockerInheritedExecution(facts, placeholder)
			projectDockerRuntimeExecution(facts, placeholder)
			projectDockerUnknownStageRunCommands(facts, placeholder)
			projectDockerUnknowns(facts, placeholder)
			removeDockerParserMetadata(facts, placeholder)
		}
	}
	projected, err := ast.InterfaceToValue(root)
	if err != nil {
		return nil, err
	}
	result := &dockerRuleInput{
		payload: projected, placeholder: placeholder, documents: map[string]ast.Value{},
		unknownValues: indexDockerUnknowns(projected, placeholder),
	}
	projectedDocs := projected.(ast.Object).Get(ast.StringTerm("document"))
	if projectedDocs != nil {
		if list, ok := projectedDocs.Value.(*ast.Array); ok {
			for i := 0; i < list.Len(); i++ {
				doc, ok := list.Elem(i).Value.(ast.Object)
				if !ok {
					continue
				}
				id := doc.Get(ast.StringTerm("id"))
				if id == nil {
					continue
				}
				if name, ok := id.Value.(ast.String); ok {
					result.documents[string(name)] = doc
					if result.hasUnknown(doc) {
						result.unknownDocuments = append(result.unknownDocuments, doc)
					}
				}
			}
		}
	}
	return result, nil
}

// Identity is assigned by the engine, not by a Rego object.union over a
// possibly unknown-bearing node. This keeps identity transport independent of
// the node's unknown security fields, as in the Terraform contract.
func stampDockerNodes(value interface{}, pointer string, node bool) {
	switch x := value.(type) {
	case []interface{}:
		for i, child := range x {
			stampDockerNodes(child, fmt.Sprintf("%s/%d", pointer, i), node)
		}
	case map[string]interface{}:
		for key, child := range x {
			isNode := false
			switch key {
			case "instructions", "stages", "calls", "package_commands", "packages", "pipelines", "trigger":
				isNode = true
			}
			token := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
			stampDockerNodes(child, pointer+"/"+token, isNode)
		}
		if node {
			x["_dd_meta"] = map[string]interface{}{"id": pointer}
		}
	}
}

// projectDockerUnknowns preserves unknowns at the policy boundary, including
// derived booleans and open inventories. A false "known" flag must not let
// negation prove absence without the unknown gate seeing the dependency.
func projectDockerUnknowns(value interface{}, placeholder string) {
	switch x := value.(type) {
	case []interface{}:
		for _, child := range x {
			projectDockerUnknowns(child, placeholder)
		}
	case map[string]interface{}:
		for _, child := range x {
			projectDockerUnknowns(child, placeholder)
		}
		projectDockerObject(x, placeholder)
	}
}

func projectDockerObject(x map[string]interface{}, placeholder string) {
	if known, ok := x["known"].(bool); ok && !known {
		x["known"] = placeholder
		for _, key := range []string{"value", "pipefail", "configured", "disabled"} {
			if _, present := x[key]; present {
				x[key] = placeholder
			}
		}
		if _, command := x["manager"]; command {
			projectDockerPackage(x, placeholder)
		}
	}
	projectDockerUnknownReference(x, placeholder)
	if executable, ok := x["executable"].(map[string]interface{}); ok && executable["known"] == placeholder {
		x["name"] = placeholder
	}
	if from, ok := x["from"].(map[string]interface{}); ok && from["known"] == placeholder {
		if _, present := x["source_stage"]; present {
			x["source_stage"] = placeholder
		}
	}
	if complete, ok := x["complete"].(bool); ok && !complete {
		x["complete"] = placeholder
		for _, name := range []string{"calls", "package_commands", "pipelines", "package_cache_mounts", "scopes"} {
			x[name] = append(asDockerList(x[name]), placeholder)
		}
	}
}

func projectDockerUnknownReference(x map[string]interface{}, placeholder string) {
	if x["kind"] == "unknown" {
		x["kind"] = placeholder
		// An unresolved image can select any registry/repository/tag, or even a
		// local stage. Empty strings here are not evidence that an exemption or
		// relationship is absent.
		for _, key := range []string{"registry", "repository", "namespace", "tag", "digest", "stage", "name", "scheme"} {
			if _, present := x[key]; present {
				x[key] = placeholder
			}
		}
		if known, ok := x["version_known"].(bool); ok && !known {
			x["version_known"], x["version_specified"] = placeholder, placeholder
		}
	}
}

func projectDockerPackage(x map[string]interface{}, placeholder string) {
	x["action"], x["subcommand"], x["assume_yes"] = placeholder, placeholder, placeholder
	for _, raw := range asDockerList(x["packages"]) {
		if pkg, ok := raw.(map[string]interface{}); ok {
			pkg["name"], pkg["pinned"] = placeholder, placeholder
		}
	}
	for _, raw := range asDockerList(x["options"]) {
		if option, ok := raw.(map[string]interface{}); ok {
			option["name"], option["value"] = placeholder, placeholder
		}
	}
	x["options"] = append(asDockerList(x["options"]), placeholder)
	x["packages"] = append(asDockerList(x["packages"]), placeholder)
}

func asDockerList(v interface{}) []interface{} {
	list, _ := v.([]interface{})
	return list
}

// gateDockerResults uses the same platform-independent tracer and substitution
// checks as Terraform. Legacy searchKey results retain their original behavior.
// Failure to check certainty fails the query instead of publishing raw results.
func (c *Inspector) gateDockerResults(ctx context.Context, qCtx *QueryContext, d *dockerRuleInput,
	payload ast.Value, results rego.ResultSet) error {
	items, err := resultItems(results)
	if err != nil || len(items) == 0 {
		return err
	}
	if err := validateDockerResultContract(qCtx, items); err != nil {
		return err
	}
	candidates, positions, err := d.candidates(items)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}
	gate, err := c.cachedDockerUnknownGate(qCtx, d.placeholder)
	if err != nil {
		return fmt.Errorf("build Dockerfile unknown gate: %w", err)
	}
	report, err := gate.Check(ctx, payload, candidates)
	if err != nil {
		return fmt.Errorf("check Dockerfile unknowns: %w", err)
	}
	drop := map[int]bool{}
	for i, verdict := range report.Verdicts {
		if verdict.Uncertain {
			drop[positions[i]] = true
		}
	}
	kept := make([]interface{}, 0, len(items)-len(drop))
	for i, item := range items {
		if !drop[i] {
			kept = append(kept, item)
		}
	}
	results[0].Bindings["result"] = kept
	contextLogger := logger.FromContext(ctx)
	contextLogger.Debug().Str("queryID", qCtx.Query.Metadata.Query).
		Int("candidates", len(candidates)).Int("suppressed", len(drop)).
		Int("partialProofEvals", report.PartialProofEvals).Int("partialProofs", report.PartialProofs).
		Msg("Checked Dockerfile unknowns")
	return nil
}

// A versioned rule cannot opt out of certainty checks by emitting legacy rows.
func validateDockerResultContract(qCtx *QueryContext, items []interface{}) error {
	requireNative := qCtx.dockerGate != nil && qCtx.dockerGate.contractChecked
	if !requireNative {
		requireNative = dockerContractRule(&qCtx.Query.Metadata)
	}
	for _, item := range items {
		if row, ok := item.(map[string]interface{}); ok {
			if _, native := row["_dd_id"]; native {
				requireNative = true
				break
			}
		}
	}
	if requireNative {
		if err := requireDockerNativeContract(qCtx); err != nil {
			return err
		}
		for _, item := range items {
			row, ok := item.(map[string]interface{})
			if !ok {
				return fmt.Errorf("dockerfile contract findings must be objects with a native node identity")
			}
			id, ok := row["_dd_id"].(string)
			if !ok || id == "" {
				return fmt.Errorf("dockerfile contract findings require a native node identity")
			}
		}
	}
	return nil
}

func (d *dockerRuleInput) candidates(items []interface{}) ([]unknowngate.Candidate, []int, error) {
	candidates := []unknowngate.Candidate{}
	positions := []int{}
	for i, item := range items {
		result, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := result["_dd_id"].(string)
		if !ok {
			continue
		}
		docID, _, _ := strings.Cut(id, "#")
		_, ok = d.documents[docID]
		if !ok {
			return nil, nil, fmt.Errorf("dockerfile finding references unknown document %q", docID)
		}
		if len(d.unknownDocuments) == 0 {
			continue
		}
		value, err := ast.InterfaceToValue(item)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, unknowngate.Candidate{Result: value, Scope: d.unknownDocuments})
		positions = append(positions, i)
	}

	return candidates, positions, nil
}

func (c *Inspector) newDockerUnknownGate(query *model.QueryMetadata, placeholder string) (*unknowngate.Gate, error) {
	modules := map[string]*ast.Module{dockerContractModuleName: ast.MustParseModule(dockerContractModule)}
	if common := c.QueryLoader.parsedCommon; common != nil {
		modules["Common"] = common.Copy()
	} else if c.QueryLoader.commonLibrary.LibraryCode != "" {
		parsed, err := ast.ParseModuleWithOpts("Common", c.QueryLoader.commonLibrary.LibraryCode, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		modules["Common"] = parsed
	}
	if generic := c.QueryLoader.parsedGeneric[query.Platform]; generic != nil {
		modules["Generic"] = generic.Copy()
	} else if library, ok := c.QueryLoader.platformLibraries[query.Platform]; ok {
		parsed, err := ast.ParseModuleWithOpts("Generic", library.LibraryCode, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, err
		}
		modules["Generic"] = parsed
	}
	parsed, err := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, err
	}
	modules["Rule"] = parsed
	data, err := c.QueryLoader.buildMergedInputData(query, nil)
	if err != nil {
		return nil, err
	}
	return unknowngate.New(unknowngate.Options{
		Placeholder: placeholder, Modules: modules, Query: "data.datadog.DatadogPolicy",
		Capabilities: safeCapabilities(), Store: inmem.NewFromReader(bytes.NewBufferString(data)), EnablePartialProof: true,
	})
}
