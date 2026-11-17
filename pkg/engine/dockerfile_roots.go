package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/cover"
)

const (
	dockerFindingFunction = "data.generic.common.finding"
	dockerfileAPIFunction = "data.datadog_scanner.dockerfile_v1"
)

// dockerContractRule reports whether a Dockerfile rule opts into the contract
// finding API. Legacy rules keep their combined-input behavior because their
// searchKey results can describe the Dockerfile as a whole. Contract rules
// use finding's canonical node identity and can be evaluated per build root.
// Library imports alone are not an opt-in: legacy text helpers use the same
// package. The loader separately enforces every versioned library's contract.
func dockerContractRule(query *model.QueryMetadata) bool {
	if query == nil || !strings.EqualFold(query.Platform, "Dockerfile") {
		return false
	}
	if _, configured, err := dockerUnitConfig(query); configured || err != nil {
		return true
	}
	module, err := ast.ParseModuleWithOpts(query.Query, query.Content, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return false
	}
	aliases := make(map[string]string, len(module.Imports))
	for _, imported := range module.Imports {
		aliases[string(imported.Name())] = imported.Path.String()
	}
	for _, rule := range module.Rules {
		found := false
		if refUsesDockerContractImportAlias(rule, module.Imports) {
			return true
		}
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if refUsesDockerNativeContract(ref, aliases) {
				found = true
				return true
			}
			return false
		})
		if found {
			return true
		}
	}
	return false
}

func refUsesDockerContractImportAlias(rule *ast.Rule, imports []*ast.Import) bool {
	for _, imported := range imports {
		path := imported.Path.String()
		if path != dockerfileAPIFunction {
			continue
		}
		alias := imported.Name()
		used := false
		ast.WalkTerms(rule, func(term *ast.Term) bool {
			if name, ok := term.Value.(ast.Var); ok && name == alias {
				used = true
				return true
			}
			return false
		})
		if used {
			return true
		}
	}
	return false
}

func refUsesDockerNativeContract(ref ast.Ref, aliases map[string]string) bool {
	refText := ref.String()
	if refUsesDockerFinding(ref, aliases) ||
		refPathHasPrefix(refText, dockerfileAPIFunction) ||
		refUsesDockerModelField(ref) {
		return true
	}
	for alias, importedPath := range aliases {
		if importedPath == dockerfileAPIFunction && refText == alias {
			return true
		}
		if strings.HasPrefix(dockerfileAPIFunction, importedPath+".") {
			resolved := alias + strings.TrimPrefix(dockerfileAPIFunction, importedPath)
			if refPathHasPrefix(refText, resolved) {
				return true
			}
		}
	}
	return false
}

func refUsesDockerModelField(ref ast.Ref) bool {
	for _, term := range ref {
		if field, ok := term.Value.(ast.String); ok && string(field) == "_dockerfile" {
			return true
		}
	}
	return false
}

func refPathHasPrefix(refText, prefix string) bool {
	return refText == prefix || strings.HasPrefix(refText, prefix+".")
}

func refUsesDockerFinding(ref ast.Ref, aliases map[string]string) bool {
	refText := ref.String()
	if refText == dockerFindingFunction {
		return true
	}
	for alias, importedPath := range aliases {
		if importedPath == dockerFindingFunction && refText == alias {
			return true
		}
		if importedPath == "data.generic.common" && refText == alias+".finding" {
			return true
		}
		if importedPath == "data.generic" && refText == alias+".common.finding" {
			return true
		}
		if importedPath == "data" && refText == alias+".generic.common.finding" {
			return true
		}
	}
	return false
}

// doRunDockerRoots evaluates a contract rule once per Dockerfile document. A
// Dockerfile is an independent build root, so uncertainty from one file cannot
// taint a finding in another. Legacy searchKey rules continue through doRun's
// combined input path.
func (c *Inspector) doRunDockerRoots(ctx context.Context, qCtx *QueryContext) (
	vulns []model.Vulnerability, moduleRaised int, moduleSeverity model.Severity, err error,
) {
	if err := ctx.Err(); err != nil {
		return nil, 0, "", err
	}
	if qCtx.dockerInput == nil {
		return nil, 0, "", errors.New("dockerfile contract evaluation requires a projected input")
	}
	if err := requireDockerNativeContract(qCtx); err != nil {
		return nil, 0, "", err
	}
	if err := validateDockerContractInput(qCtx.dockerInput.payload, qCtx.dockerInput.placeholder); err != nil {
		return nil, 0, "", err
	}
	if c.enableCoverageReport && qCtx.coverage == nil {
		qCtx.coverage = cover.New()
	}
	roots, err := dockerRoots(qCtx.dockerInput)
	if err != nil {
		return nil, 0, "", err
	}
	roots, err = dockerUnitRoots(&qCtx.Query.Metadata, roots)
	if err != nil {
		return nil, 0, "", err
	}
	lineInfo := dockerUnitLineInfo{query: qCtx}
	defer lineInfo.release()
	for _, root := range roots {
		lineInfo.advance(root)
		if err := ctx.Err(); err != nil {
			return nil, 0, "", err
		}
		rootVulns, raised, severity, runErr := c.doRunDockerRoot(ctx, qCtx, root)
		if runErr != nil {
			return nil, 0, "", runErr
		}
		if err := ctx.Err(); err != nil {
			return nil, 0, "", err
		}
		vulns = append(vulns, rootVulns...)
		moduleRaised += raised
		if moduleSeverity == "" {
			moduleSeverity = severity
		}
	}
	return vulns, moduleRaised, moduleSeverity, nil
}

type dockerBuildRoot struct {
	id              string
	doc             ast.Object
	term            *ast.Term
	instructionUnit bool
	stageUnit       bool
	unknownValue    string
}

// Instruction units from one file share its source tree until the file is
// finished. DecodeQueryResults otherwise releases it after every unit.
type dockerUnitLineInfo struct {
	query  *QueryContext
	fileID string
}

func (l *dockerUnitLineInfo) advance(root dockerBuildRoot) {
	if !l.query.discardLineInfoAfterUse || (!root.instructionUnit && !root.stageUnit) {
		return
	}
	if l.fileID != root.id {
		l.release()
		l.fileID = root.id
	}
}

func (l *dockerUnitLineInfo) release() {
	if l.fileID == "" {
		return
	}
	if file := l.query.Files[l.fileID]; file != nil {
		file.DiscardLineInfoDocument()
		file.ReleaseSubstringIndex()
	}
	l.fileID = ""
}

func dockerRoots(input *dockerRuleInput) ([]dockerBuildRoot, error) {
	root, ok := input.payload.(ast.Object)
	if !ok {
		return nil, errors.New("dockerfile projected input must be an object")
	}
	documentsTerm := root.Get(ast.StringTerm("document"))
	if documentsTerm == nil {
		return nil, nil
	}
	documents, ok := documentsTerm.Value.(*ast.Array)
	if !ok {
		return nil, errors.New("dockerfile projected documents must be an array")
	}
	roots := make([]dockerBuildRoot, 0, documents.Len())
	for i := 0; i < documents.Len(); i++ {
		term := documents.Elem(i)
		doc, ok := term.Value.(ast.Object)
		if !ok || doc.Get(ast.StringTerm("_dockerfile")) == nil {
			continue
		}
		idTerm := doc.Get(ast.StringTerm("id"))
		if idTerm == nil {
			continue
		}
		id, ok := idTerm.Value.(ast.String)
		if !ok {
			continue
		}
		if _, exists := input.documents[string(id)]; !exists {
			continue
		}
		roots = append(roots, dockerBuildRoot{id: string(id), doc: doc, term: term, unknownValue: input.placeholder})
	}
	return roots, nil
}

func (c *Inspector) doRunDockerRoot(ctx context.Context, qCtx *QueryContext, root dockerBuildRoot) (
	[]model.Vulnerability, int, model.Severity, error,
) {
	payload, err := dockerRootPayload(qCtx.dockerInput, root)
	if err != nil {
		return nil, 0, "", err
	}
	childInput := &dockerRuleInput{
		payload:       payload,
		unknownValues: qCtx.dockerInput.unknownValues,
		placeholder:   qCtx.dockerInput.placeholder,
		documents:     map[string]ast.Value{root.id: qCtx.dockerInput.documents[root.id]},
	}
	if childInput.hasUnknown(root.doc) {
		childInput.unknownDocuments = []ast.Value{root.doc}
	}
	child := *qCtx
	child.payload = &payload
	child.dockerInput = childInput
	child.dockerGate = qCtx.dockerGate
	child.coverage = qCtx.coverage
	if root.instructionUnit || root.stageUnit {
		child.discardLineInfoAfterUse = false
	}
	if qCtx.findings != nil {
		child.findings = newFindingSet(qCtx.findings.kept != nil, qCtx.findings.routing)
	}
	return c.doRun(ctx, &child)
}

func dockerRootPayload(input *dockerRuleInput, root dockerBuildRoot) (ast.Value, error) {
	full, ok := input.payload.(ast.Object)
	if !ok {
		return nil, errors.New("dockerfile projected input must be an object")
	}
	child := ast.NewObjectWithCapacity(full.Len())
	if err := full.Iter(func(key, value *ast.Term) error {
		if key.Value.Compare(ast.String("document")) != 0 {
			child.Insert(key, value)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	child.Insert(ast.StringTerm("document"), ast.NewTerm(ast.NewArray(root.term)))
	return child, nil
}
