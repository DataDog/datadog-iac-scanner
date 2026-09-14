/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package terraform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/builder/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/functions"
	"github.com/DataDog/datadog-iac-scanner/pkg/tfpath"
	"github.com/DataDog/datadog-iac-scanner/pkg/vfs"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// iamPolicyDocumentTypeMarker is a cheap content gate before parsing; the parser
// still matches the block type exactly below.
const iamPolicyDocumentType = "aws_iam_policy_document"

var iamPolicyDocumentTypeMarker = []byte(iamPolicyDocumentType)

// iamPolicyDocumentTypePrefix catches HCL unicode-escaped spellings such as
// aws_iam_pol\u0069cy_document that decode to the same label after lexing.
var iamPolicyDocumentTypePrefix = []byte("aws_iam_pol")

type dataSourcePolicyCondition struct {
	Test     string   `json:"test,omitempty"`
	Variable string   `json:"variable,omitempty"`
	Values   []string `json:"values,omitempty"`
}

type dataSourcePolicyPrincipal struct {
	Type        string   `json:"type,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type dataSourcePolicyStatement struct {
	Actions       []string                  `json:"actions"`
	Condition     dataSourcePolicyCondition `json:"condition"`
	Effect        string                    `json:"effect"`
	NotActions    []string                  `json:"not_actions"`
	NotPrincipals dataSourcePolicyPrincipal `json:"not_principals"`
	NotResources  []string                  `json:"not_resources"`
	Principals    dataSourcePolicyPrincipal `json:"principals"`
	Resources     []string                  `json:"resources"`
	Sid           string                    `json:"sid"`
}

type dataSourcePolicy struct {
	ID        string                      `json:"id"`
	Statement []dataSourcePolicyStatement `json:"statement"`
	Version   string                      `json:"version"`
}

type dataSource struct {
	Value dataSourcePolicy `json:"value"`
}

type convertedPolicyCondition map[string]map[string][]string
type convertedPolicyPrincipal map[string][]string

type convertedPolicyStatement struct {
	Actions       []string                 `json:"Actions,omitempty"`
	Condition     convertedPolicyCondition `json:"Condition,omitempty"`
	Effect        string                   `json:"Effect,omitempty"`
	NotActions    []string                 `json:"Not_actions,omitempty"`
	NotPrincipals convertedPolicyPrincipal `json:"Not_principals,omitempty"`
	NotResources  []string                 `json:"Not_resources,omitempty"`
	Principals    convertedPolicyPrincipal `json:"Principals,omitempty"`
	Resources     []string                 `json:"Resources,omitempty"`
	Sid           string                   `json:"Sid,omitempty"`
}

type convertedPolicy struct {
	ID        string                     `json:"Id,omitempty"`
	Statement []convertedPolicyStatement `json:"Statement,omitempty"`
	Version   string                     `json:"Version,omitempty"`
}

func getDataSourcePolicy(
	ctx context.Context, fsys vfs.FS, currentPath string, inputVariables converter.VariableMap, allow map[string]struct{}, keep string,
) converter.VariableMap {
	contextLogger := logger.FromContext(ctx)
	tfFiles := hclConfigFiles(ctx, fsys, currentPath, allow, keep)
	if len(tfFiles) == 0 {
		return inputVariables
	}
	jsonMap := make(map[string]map[string]string)
	for _, tfFile := range tfFiles {
		content, readErr := fsys.ReadFile(filepath.Clean(tfFile))
		if readErr != nil {
			contextLogger.Debug().Msgf("Error trying to read file %s for data source.", tfFile)
			continue
		}
		if !fileMayDeclareIAMPolicyDocument(content) {
			continue
		}
		if tfpath.IsJSONConfig(tfFile) {
			collectJSONDataSourcePolicies(ctx, content, tfFile, inputVariables, jsonMap)
			continue
		}
		collectHCLDataSourcePolicies(ctx, content, tfFile, inputVariables, jsonMap)
	}
	policyResource := map[string]map[string]map[string]string{
		"aws_iam_policy_document": jsonMap,
	}
	data, err := gocty.ToCtyValue(policyResource, cty.Map(cty.Map(cty.Map(cty.String))))
	if err != nil {
		contextLogger.Error().Msgf("Error trying to convert policy to cty value: %s", err)
		return inputVariables
	}

	inputVariables["data"] = data
	return inputVariables
}

func collectHCLDataSourcePolicies(
	ctx context.Context, content []byte, tfFile string, inputVariables converter.VariableMap, jsonMap map[string]map[string]string,
) {
	contextLogger := logger.FromContext(ctx)
	parsedFile, diags := parseFileContent(content, tfFile, true)
	if diags != nil && diags.HasErrors() {
		contextLogger.Debug().Msgf("Error trying to parse file %s for data source.", tfFile)
		return
	}
	if parsedFile == nil {
		contextLogger.Debug().Msgf("Error trying to parse file %s for data source.", tfFile)
		return
	}
	body, ok := parsedFile.Body.(*hclsyntax.Body)
	if !ok {
		return
	}
	for _, block := range body.Blocks {
		if block.Type == terraformDataIdentifier &&
			len(block.Labels) > 1 &&
			block.Labels[0] == iamPolicyDocumentType {
			jsonMap[block.Labels[1]] = map[string]string{
				"json": parseDataSourceBody(ctx, block.Body, inputVariables, nil),
			}
		}
	}
}

func collectJSONDataSourcePolicies(
	ctx context.Context, src []byte, filename string, inputVariables converter.VariableMap, jsonMap map[string]map[string]string,
) {
	parsed, diags := hcljson.Parse(src, filename)
	if diags.HasErrors() {
		return
	}
	content, _, _ := parsed.Body.PartialContent(jsonConfigSchema)
	if content == nil {
		return
	}
	for _, block := range content.Blocks {
		if block.Type != terraformDataIdentifier || len(block.Labels) < 2 {
			continue
		}
		if block.Labels[0] != iamPolicyDocumentType {
			continue
		}
		jsonMap[block.Labels[1]] = map[string]string{
			"json": parseDataSourceBody(ctx, block.Body, inputVariables, src),
		}
	}
}

// fileMayDeclareIAMPolicyDocument is a fast precheck before parseFileContent.
// A literal substring match covers the common case; lexer decoding handles
// escaped block-type labels that do not appear verbatim in source bytes.
func fileMayDeclareIAMPolicyDocument(content []byte) bool {
	if bytes.Contains(content, iamPolicyDocumentTypeMarker) {
		return true
	}
	if !bytes.Contains(content, iamPolicyDocumentTypePrefix) {
		return false
	}
	return scanForIAMPolicyDocumentDataBlock(content)
}

func scanForIAMPolicyDocumentDataBlock(content []byte) bool {
	tokens, diags := hclsyntax.LexConfig(content, "", hcl.InitialPos)
	if diags.HasErrors() {
		return false
	}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type != hclsyntax.TokenIdent || string(tokens[i].Bytes) != terraformDataIdentifier {
			continue
		}
		label, next := decodeQuotedBlockLabel(tokens, i+1)
		if label == iamPolicyDocumentType {
			return true
		}
		i = next
	}
	return false
}

func decodeQuotedBlockLabel(tokens hclsyntax.Tokens, start int) (label string, next int) {
	for start < len(tokens) {
		switch tokens[start].Type {
		case hclsyntax.TokenNewline, hclsyntax.TokenComment:
			start++
		case hclsyntax.TokenOQuote:
			goto parseQuoted
		default:
			return "", start
		}
	}
	return "", start

parseQuoted:
	var b strings.Builder
	for j := start + 1; j < len(tokens); j++ {
		switch tokens[j].Type {
		case hclsyntax.TokenCQuote:
			return b.String(), j
		case hclsyntax.TokenQuotedLit:
			s, litDiags := hclsyntax.ParseStringLiteralToken(tokens[j])
			if litDiags.HasErrors() {
				return "", j
			}
			b.WriteString(s)
		default:
			return "", j
		}
	}
	return "", start
}

func decodeDataSourcePolicy(ctx context.Context, value cty.Value) dataSourcePolicy {
	contextLogger := logger.FromContext(ctx)
	jsonified, err := ctyjson.Marshal(cty.UnknownAsNull(value), cty.DynamicPseudoType)
	if err != nil {
		contextLogger.Warn().Msgf("Error trying to decode data source block: %s", err)
		return dataSourcePolicy{}
	}
	var data dataSource
	err = json.Unmarshal(jsonified, &data)
	if err != nil {
		contextLogger.Error().Msgf("Error trying to encode data source json: %s", err)
		return dataSourcePolicy{}
	}
	return data.Value
}

func getPrincipalSpec() *hcldec.ObjectSpec {
	return &hcldec.ObjectSpec{
		"type": &hcldec.AttrSpec{
			Name:     "type",
			Type:     cty.String,
			Required: false,
		},
		"identifiers": &hcldec.AttrSpec{
			Name:     "identifiers",
			Type:     cty.List(cty.String),
			Required: false,
		},
	}
}

func getConditionalSpec() *hcldec.ObjectSpec {
	return &hcldec.ObjectSpec{
		"test": &hcldec.AttrSpec{
			Name:     "test",
			Type:     cty.String,
			Required: false,
		},
		"variable": &hcldec.AttrSpec{
			Name:     "variable",
			Type:     cty.String,
			Required: false,
		},
		"values": &hcldec.AttrSpec{
			Name:     "values",
			Type:     cty.List(cty.String),
			Required: false,
		},
	}
}

func getStatementSpec() *hcldec.BlockListSpec {
	return &hcldec.BlockListSpec{
		TypeName: "statement",
		Nested: &hcldec.ObjectSpec{
			"sid": &hcldec.AttrSpec{
				Name:     "sid",
				Type:     cty.String,
				Required: false,
			},
			"effect": &hcldec.AttrSpec{
				Name:     "effect",
				Type:     cty.String,
				Required: false,
			},
			"actions": &hcldec.AttrSpec{
				Name:     "actions",
				Type:     cty.List(cty.String),
				Required: false,
			},
			"not_actions": &hcldec.AttrSpec{
				Name:     "not_actions",
				Type:     cty.List(cty.String),
				Required: false,
			},
			"resources": &hcldec.AttrSpec{
				Name:     "resources",
				Type:     cty.List(cty.String),
				Required: false,
			},
			"not_resources": &hcldec.AttrSpec{
				Name:     "not_resources",
				Type:     cty.List(cty.String),
				Required: false,
			},
			"principals": &hcldec.BlockSpec{
				TypeName: "principals",
				Nested:   getPrincipalSpec(),
			},
			"not_principals": &hcldec.BlockSpec{
				TypeName: "not_principals",
				Nested:   getPrincipalSpec(),
			},
			"condition": &hcldec.BlockSpec{
				TypeName: "condition",
				Nested:   getConditionalSpec(),
			},
		},
	}
}

func parseDataSourceBody(ctx context.Context, body hcl.Body, inputVariables converter.VariableMap, src []byte) string {
	if syn, ok := body.(*hclsyntax.Body); ok {
		resolveDataResources(ctx, syn)
	}
	contextLogger := logger.FromContext(ctx)
	dataSourceSpec := &hcldec.ObjectSpec{
		"id": &hcldec.AttrSpec{
			Name:     "id",
			Type:     cty.String,
			Required: false,
		},
		"version": &hcldec.AttrSpec{
			Name:     "version",
			Type:     cty.String,
			Required: false,
		},
		"statement": getStatementSpec(),
	}

	target, decodeErrs := hcldec.Decode(body, dataSourceSpec, &hcl.EvalContext{
		Variables: inputVariables,
		Functions: functions.TerraformFuncs,
	})

	// Dismiss unresolvable variable references; both leave the field as
	// cty.DynamicVal which cty.UnknownAsNull handles below.
	// "Unsupported attribute" is narrowed by Detail to avoid swallowing
	// unrelated attribute errors on non-variable objects.
	for _, decErr := range decodeErrs {
		isUnknownVar := decErr.Summary == "Unknown variable"
		isUnsupportedAttrOnVar := decErr.Summary == "Unsupported attribute" &&
			strings.Contains(decErr.Detail, "does not have an attribute named")
		if !isUnknownVar && !isUnsupportedAttrOnVar {
			contextLogger.Debug().Msgf("Error trying to eval data source block: %s", decErr.Summary)
			return ""
		}
		contextLogger.Debug().Msgf("Dismissed unresolvable reference when decoding policy: %s: %s", decErr.Summary, decErr.Detail)
	}

	dataSourceJSON := decodeDataSourcePolicy(ctx, target)
	if len(src) > 0 {
		fillJSONPolicyResources(dataSourceJSON.Statement, body, src)
	}
	convertedDataSource := convertedPolicy{
		ID:      dataSourceJSON.ID,
		Version: dataSourceJSON.Version,
	}
	statements := make([]convertedPolicyStatement, len(dataSourceJSON.Statement))
	for idx := range dataSourceJSON.Statement {
		var convertedCondition convertedPolicyCondition
		if dataSourceJSON.Statement[idx].Condition.Variable != "" {
			convertedCondition = convertedPolicyCondition{
				dataSourceJSON.Statement[idx].Condition.Test: map[string][]string{
					dataSourceJSON.Statement[idx].Condition.Variable: dataSourceJSON.Statement[idx].Condition.Values,
				},
			}
		}
		var convertedPrincipal convertedPolicyPrincipal
		if dataSourceJSON.Statement[idx].Principals.Type != "" {
			convertedPrincipal = convertedPolicyPrincipal{
				dataSourceJSON.Statement[idx].Principals.Type: dataSourceJSON.Statement[idx].Principals.Identifiers,
			}
		}
		var convertedNotPrincipal convertedPolicyPrincipal
		if dataSourceJSON.Statement[idx].NotPrincipals.Type != "" {
			convertedNotPrincipal = convertedPolicyPrincipal{
				dataSourceJSON.Statement[idx].NotPrincipals.Type: dataSourceJSON.Statement[idx].NotPrincipals.Identifiers,
			}
		}

		convertedStatement := convertedPolicyStatement{
			Actions:       dataSourceJSON.Statement[idx].Actions,
			Effect:        dataSourceJSON.Statement[idx].Effect,
			NotActions:    dataSourceJSON.Statement[idx].NotActions,
			NotResources:  dataSourceJSON.Statement[idx].NotResources,
			Resources:     dataSourceJSON.Statement[idx].Resources,
			Sid:           dataSourceJSON.Statement[idx].Sid,
			Condition:     convertedCondition,
			NotPrincipals: convertedNotPrincipal,
			Principals:    convertedPrincipal,
		}
		statements[idx] = convertedStatement
	}
	convertedDataSource.Statement = statements
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(convertedDataSource)
	if err != nil {
		contextLogger.Error().Msgf("Error trying to encoding data source json: %s", err)
		return ""
	}
	return buffer.String()
}

func fillJSONPolicyResources(statements []dataSourcePolicyStatement, body hcl.Body, src []byte) {
	lists := jsonPolicyResourceLists(body, src)
	for i := range statements {
		if i >= len(lists) {
			return
		}
		if jsonPolicyResourcesMissing(statements[i].Resources) && len(lists[i]) > 0 {
			statements[i].Resources = lists[i]
		}
	}
}

func jsonPolicyResourcesMissing(resources []string) bool {
	if len(resources) == 0 {
		return true
	}
	for _, resource := range resources {
		if resource != "" {
			return false
		}
	}
	return true
}

func jsonPolicyResourceLists(body hcl.Body, src []byte) [][]string {
	if lists := jsonPolicyResourceListsFromBlocks(body, src); len(lists) > 0 {
		return lists
	}
	return jsonPolicyResourceListsFromAttr(body, src)
}

func jsonPolicyResourceListsFromBlocks(body hcl.Body, src []byte) [][]string {
	content, _, _ := body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "statement"}},
	})
	if content == nil {
		return nil
	}
	out := make([][]string, 0, len(content.Blocks))
	for _, block := range content.Blocks {
		attrs, _ := block.Body.JustAttributes()
		out = append(out, jsonPolicyResourcesFromAttr(attrs["resources"], src))
	}
	return out
}

func jsonPolicyResourceListsFromAttr(body hcl.Body, src []byte) [][]string {
	attrs, _ := body.JustAttributes()
	attr, ok := attrs["statement"]
	if !ok {
		return nil
	}
	statements, diags := hcl.ExprList(attr.Expr)
	if diags.HasErrors() {
		return nil
	}
	out := make([][]string, 0, len(statements))
	for _, statement := range statements {
		pairs, pairDiags := hcl.ExprMap(statement)
		if pairDiags.HasErrors() {
			out = append(out, nil)
			continue
		}
		var resources hcl.Expression
		for _, pair := range pairs {
			key, keyDiags := pair.Key.Value(&hcl.EvalContext{})
			if keyDiags.HasErrors() || !key.IsKnown() || key.Type() != cty.String || key.AsString() != "resources" {
				continue
			}
			resources = pair.Value
			break
		}
		out = append(out, jsonPolicyResourcesFromExpr(resources, src))
	}
	return out
}

func jsonPolicyResourcesFromAttr(attr *hcl.Attribute, src []byte) []string {
	if attr == nil {
		return nil
	}
	return jsonPolicyResourcesFromExpr(attr.Expr, src)
}

func jsonPolicyResourcesFromExpr(expr hcl.Expression, src []byte) []string {
	if expr == nil {
		return nil
	}
	items, diags := hcl.ExprList(expr)
	if diags.HasErrors() {
		return nil
	}
	resources := make([]string, 0, len(items))
	for _, item := range items {
		if s := jsonPolicyResourceString(item, src); s != "" {
			resources = append(resources, s)
		}
	}
	return resources
}

func jsonPolicyResourceString(expr hcl.Expression, src []byte) string {
	val, diags := expr.Value(&hcl.EvalContext{})
	if !diags.HasErrors() && val.IsWhollyKnown() && !val.IsNull() && val.Type() == cty.String {
		return val.AsString()
	}
	s := wrapJSONRange(expr.Range(), "", src)
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		inner := s[2 : len(s)-1]
		if !strings.Contains(inner, "${") {
			return inner
		}
	}
	return s
}

// resolveDataResources resolves the data resources expressions into LiteralValueExpr
func resolveDataResources(ctx context.Context, body *hclsyntax.Body) {
	for _, block := range body.Blocks {
		if resources, ok := block.Body.Attributes["resources"]; ok &&
			block.Type == "statement" {
			resolveTuple(ctx, resources.Expr)
		}
	}
}

func resolveTuple(ctx context.Context, expr hclsyntax.Expression) {
	contextLogger := logger.FromContext(ctx)
	e := engine.Engine{}
	if v, ok := expr.(*hclsyntax.TupleConsExpr); ok {
		for i, ex := range v.Exprs {
			striExpr, err := e.ExpToString(ctx, ex)

			if err != nil {
				if !errors.Is(err, engine.ErrNullLiteral) {
					contextLogger.Error().Msgf("Error trying to ExpToString: %s", err)
				}
				continue
			}

			v.Exprs[i] = &hclsyntax.LiteralValueExpr{
				Val:      cty.StringVal(striExpr),
				SrcRange: v.Exprs[i].Range(),
			}
		}
	}
}
