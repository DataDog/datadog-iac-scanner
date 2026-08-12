/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
)

// Constants to describe what kind of file refers
const (
	KindTerraform     FileKind = "TF"
	KindTerraformPlan FileKind = "TFPLAN"
	KindBICEP         FileKind = "BICEP"
	KindDOCKER        FileKind = "DOCKER"
	KindJSON          FileKind = "JSON"
	KindYAML          FileKind = "YAML"
	KindYML           FileKind = "YML"
	KindPROTO         FileKind = "PROTO"
	KindCOMMON        FileKind = "*"
	KindHELM          FileKind = "HELM"
	KindBUILDAH       FileKind = "SH"
	KindCFG           FileKind = "CFG"
	KindINI           FileKind = "INI"
)

// Constants to describe commands given from comments
const (
	IgnoreLine    CommentCommand = "ignore-line"
	IgnoreBlock   CommentCommand = "ignore-block"
	IgnoreComment CommentCommand = "ignore-comment"
)

// Suppression kinds map to SARIF 2.1.0 `suppressions[].kind`.
const (
	SuppressionKindInSource = "inSource"
)

// Suppression justifications surfaced in SARIF `suppressions[].justification`.
// `IgnoreComment` covers both `ignore-line` and `ignore-block` because
// `LinesIgnore` flattens block directives to individual line numbers, so the
// originating directive is no longer recoverable at suppression time.
const (
	SuppressionJustificationIgnoreComment = "dd-iac-scan ignore"
	SuppressionJustificationDisableInFile = "dd-iac-scan disable"
)

// Constants to describe vulnerability's severity
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
	SeverityTrace    = "TRACE"
)

// Arrays to group all constants of one type
var (
	AllSeverities = []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
		SeverityTrace,
	}
)

var (
	// DDCommentRgxp identifies dd-iac-scan inline suppression comments
	DDCommentRgxp = regexp.MustCompile(`(^|\n)((/{2})|#|;)*\s*dd-iac-scan\s*`)
	// DDGetContentCommentRgxp extracts the dd-iac-scan comment content
	DDGetContentCommentRgxp = regexp.MustCompile(`(^|\n)((/{2})|#|;)*\s*dd-iac-scan([^\n]*)\n`)
	// DDCommentRgxpYaml identifies dd-iac-scan suppression comments in YAML
	DDCommentRgxpYaml = regexp.MustCompile(`((/{2})|#)*\s*dd-iac-scan\s*(ignore-line|ignore-block)\s*\n*$`)
)

// VulnerabilityLines is the representation of the found line for issue
type VulnerabilityLines struct {
	Line                   int
	VulnLines              *[]CodeLine
	LineWithVulnerability  string
	ResolvedFile           string
	VulnerablilityLocation ResourceLocation
	RemediationLocation    ResourceLocation
	ResourceSource         string
	FileSource             []string
	BlockLocation          ResourceLocation
}

// CommentCommand represents a command given from a comment
type CommentCommand string

// FileKind is the extension of a file
type FileKind string

// Severity of the vulnerability
type Severity string

// CodeLine is the lines containing and adjacent to the vulnerability line with their respective positions
type CodeLine struct {
	Position int
	Line     string
}

// ResourceLocation is the line information of the resource with their respective start and end positions
type ResourceLocation struct {
	Start ResourceLine
	End   ResourceLine
}

// ResourceLine is the line information of the resource with their respective positions
type ResourceLine struct {
	Col  int
	Line int
}

// ExtractedPathObject is the struct that contains the path location of extracted source
// and a boolean to check if it is a local source
type ExtractedPathObject struct {
	Path      string
	LocalPath bool
}

// CommentsCommands list of commands on a file that will be parsed
type CommentsCommands map[string]string

// FileMetadata is a representation of basic information and content of a file
type FileMetadata struct {
	ID               string `db:"id"`
	ScanID           string `db:"scan_id"`
	Document         Document
	LineInfoDocument map[string]interface{}
	// LineInfoLoader, when set, lazily reconstructs LineInfoDocument (a
	// second full copy of the parsed document tree, kept intact with
	// _dd_lines markers purely to resolve a confirmed finding's source line)
	// on first access via EnsureLineInfoDocument, instead of every file
	// paying for it eagerly. Only a small fraction of scanned files ever
	// have a finding, so most never need it. nil means LineInfoDocument is
	// already populated (or intentionally left unset).
	LineInfoLoader    func(ctx context.Context, f *FileMetadata) (map[string]interface{}, error)
	lineInfoOnce      sync.Once
	lineInfoErr       error
	OriginalData      string   `db:"orig_data"`
	Kind              FileKind `db:"kind"`
	FilePath          string   `db:"file_path"`
	HelmID            string
	IDInfo            map[int]interface{}
	Commands          CommentsCommands
	LinesIgnore       []int
	ResolvedFiles     map[string]ResolvedFile
	LinesOriginalData *[]string
	IsMinified        bool
	// ModuleCallChain: synthetic rows for instantiated local modules; used in SARIF fingerprint (Terraform only).
	ModuleCallChain string
	// Platform is the lowercased platform the file was classified as (e.g.
	// "ansible", "kubernetes", "terraform"); "" when undetermined. Used by the
	// engine to evaluate each query only against documents of its own platform.
	Platform string
}

// Clone returns a shallow copy of f. FileMetadata carries a sync.Once (for
// EnsureLineInfoDocument's memoization), so a plain `x := *f` struct-literal
// copy would duplicate its current state (and trips go vet's copylocks
// check); Clone instead copies field-by-field and gives the result its own,
// independent, not-yet-fired memoization state.
func (f *FileMetadata) Clone() *FileMetadata {
	return &FileMetadata{
		ID:                f.ID,
		ScanID:            f.ScanID,
		Document:          f.Document,
		LineInfoDocument:  f.LineInfoDocument,
		LineInfoLoader:    f.LineInfoLoader,
		OriginalData:      f.OriginalData,
		Kind:              f.Kind,
		FilePath:          f.FilePath,
		HelmID:            f.HelmID,
		IDInfo:            f.IDInfo,
		Commands:          f.Commands,
		LinesIgnore:       f.LinesIgnore,
		ResolvedFiles:     f.ResolvedFiles,
		LinesOriginalData: f.LinesOriginalData,
		IsMinified:        f.IsMinified,
		ModuleCallChain:   f.ModuleCallChain,
		Platform:          f.Platform,
	}
}

// EnsureLineInfoDocument lazily materializes LineInfoDocument via
// LineInfoLoader on first access, memoizing the result (or error) so repeat
// calls are cheap. Safe for concurrent callers. No-op if LineInfoLoader is
// nil, i.e. LineInfoDocument is already populated (or intentionally unset).
func (f *FileMetadata) EnsureLineInfoDocument(ctx context.Context) error {
	if f.LineInfoLoader == nil {
		return nil
	}
	f.lineInfoOnce.Do(func() {
		doc, err := f.LineInfoLoader(ctx, f)
		if err != nil {
			f.lineInfoErr = err
			return
		}
		f.LineInfoDocument = doc
	})
	return f.lineInfoErr
}

// QueryMetadata is a representation of general information about a query
type QueryMetadata struct {
	InputData string
	Query     string
	Content   string
	Metadata  map[string]interface{}
	Platform  string
	CWE       string
	// special field for generic queries
	// represents how many queries are aggregated into a single rego file
	Aggregation  int
	Experimental bool
}

// Vulnerability is a representation of a detected vulnerability in scanned files
// after running a query
type Vulnerability struct {
	ID                    int              `json:"id"`
	ScanID                string           `db:"scan_id" json:"-"`
	FileID                string           `db:"file_id" json:"-"`
	FileName              string           `db:"file_name" json:"fileName"`
	QueryID               string           `db:"query_id" json:"queryID"`
	LegacyQueryID         string           `db:"legacy_query_id" json:"legacyQueryID"`
	QueryName             string           `db:"query_name" json:"queryName"`
	QueryURI              string           `json:"-"`
	Category              string           `json:"category"`
	Experimental          bool             `json:"experimental"`
	Description           string           `json:"description"`
	DescriptionID         string           `json:"descriptionID"`
	Platform              string           `db:"platform" json:"platform"`
	CWE                   string           `db:"cwe" json:"cwe"`
	Severity              Severity         `json:"severity"`
	Line                  int              `json:"line"`
	VulnerabilityLocation ResourceLocation `json:"resourceLocation"`
	VulnLines             *[]CodeLine      `json:"vulnLines"`
	ResourceType          string           `db:"resource_type" json:"resourceType"`
	ResourceName          string           `db:"resource_name" json:"resourceName"`
	SearchKey             string           `db:"search_key" json:"searchKey"`
	SearchLine            int              `db:"search_line" json:"searchLine"`
	SearchValue           string           `db:"search_value" json:"searchValue"`
	Value                 *string          `db:"value" json:"value"`
	Output                string           `json:"-"`
	CloudProvider         string           `json:"cloud_provider"`
	Remediation           string           `db:"remediation" json:"remediation"`
	RemediationType       string           `db:"remediation_type" json:"remediation_type"`
	RemediationLocation   ResourceLocation `json:"remediationLocation"`
	QueryDuration         time.Duration    `json:"query_duration"`
	LineWithVulnerability string           `json:"lineWithVulnerability"`
	ResourceSource        string           `json:"resourceSource"`
	FileSource            []string         `json:"fileSource"`
	BlockLocation         ResourceLocation `json:"blockLocation"`
	Frameworks            []Framework      `json:"frameworks,omitempty"`
	// IsSuppressed marks a finding as kept-for-SARIF but excluded from
	// severity counters; the kind/justification map directly to SARIF
	// `suppressions[]`.
	IsSuppressed             bool   `json:"isSuppressed,omitempty"`
	SuppressionKind          string `json:"suppressionKind,omitempty"`
	SuppressionJustification string `json:"suppressionJustification,omitempty"`
	// ModuleCallChain: local-module instantiation path; empty for root resources; folded into fingerprint.
	ModuleCallChain string `json:"moduleCallChain,omitempty"`
}

// Framework represents a framework mapping for a query
type Framework struct {
	Framework        string `json:"framework"`
	FrameworkVersion string `json:"framework_version"`
	Requirement      string `json:"requirement"`
	Control          string `json:"control"`
}

// QueryConfig is a struct that contains the fileKind and platform of the rego query
type QueryConfig struct {
	FileKind []FileKind
	Platform string
}

// ResolvedFiles keeps the information of all file/template resolved
type ResolvedFiles struct {
	File     []ResolvedHelm
	Excluded []string
}

// ResolvedHelm keeps the information of a file/template resolved
type ResolvedHelm struct {
	FileName     string
	Content      []byte
	OriginalData []byte
	SplitID      string
	IDInfo       map[int]interface{}
}

// Extensions represents a list of supported extensions
type Extensions map[string]struct{}

// Include returns true if an extension is included in supported extensions listed
// otherwise returns false
func (e Extensions) Include(ext string) bool {
	_, b := e[ext]

	return b
}

// LineObject is the struct that will hold line information for each key
type LineObject struct {
	Line int                      `json:"_dd_line"`
	Arr  []map[string]*LineObject `json:"_dd_arr,omitempty"`
}

// MatchedFilesRegex returns the regex rule to identify if an extension is supported or not
func (e Extensions) MatchedFilesRegex() string {
	if len(e) == 0 {
		return "NO_MATCHED_FILES"
	}

	var parts []string
	for ext := range e {
		parts = append(parts, "\\"+ext)
	}

	sort.Strings(parts)

	return "(.*)(" + strings.Join(parts, "|") + ")$"
}

// FileMetadatas is a slice of FileMetadata pointers
type FileMetadatas []*FileMetadata

// ToMap creates a map of FileMetadatas, which the key is the FileMetadata ID and the value is a pointer to the FileMetadata
func (m FileMetadatas) ToMap() map[string]*FileMetadata {
	c := make(map[string]*FileMetadata, len(m))
	for i := 0; i < len(m); i++ {
		c[m[i].ID] = m[i]
	}
	return c
}

// Documents
type Documents struct {
	Documents []Document `json:"document"`
}

// Document
type Document map[string]interface{}

// Combine merge documents from FileMetadatas using the ID as reference for Document ID and FileName as reference for file
func (m FileMetadatas) Combine(ctx context.Context, lineInfo bool) Documents {
	contextLogger := logger.FromContext(ctx)
	documents := Documents{Documents: make([]Document, 0, len(m))}
	for _, f := range m {
		_, ignore := f.Commands["ignore"]
		if len(f.Document) == 0 {
			continue
		}
		if ignore {
			contextLogger.Debug().Msgf("Ignoring file %s", f.FilePath)
			continue
		}
		if lineInfo {
			if err := f.EnsureLineInfoDocument(ctx); err != nil {
				contextLogger.Err(err).Msgf("failed to build line-info document for file %s", f.FilePath)
				continue
			}
			f.LineInfoDocument["id"] = f.ID
			f.LineInfoDocument["file"] = f.FilePath
			documents.Documents = append(documents.Documents, f.LineInfoDocument)
		} else {
			f.Document["id"] = f.ID
			f.Document["file"] = f.FilePath
			documents.Documents = append(documents.Documents, f.Document)
		}
	}
	return documents
}

// AnalyzedPaths is a slice of types and excluded files obtained from the Analyzer
type AnalyzedPaths struct {
	Types        []string
	Exc          []string
	ExpectedLOC  int
	FilePlatform map[string]string
	Inventory    []string
	ChartRoots   []string
	TotalFiles   int
	ContentCache map[string][]byte
}

// ResolvedFileSplit is a struct that contains the information of a resolved file, the path and the lines of the file
type ResolvedFileSplit struct {
	Path  string
	Lines []string
}

// ResolvedFile is a struct that contains the information of a resolved file, the path and the content in bytes of the file
type ResolvedFile struct {
	Path         string
	Content      []byte
	LinesContent *[]string
}

type SarifResourceLocation struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type SarifFix struct {
	ArtifactChanges []ArtifactChange `json:"artifactChanges"`
	Description     FixMessage       `json:"description"`
}

type ArtifactChange struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []FixReplacement `json:"replacements"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type FixReplacement struct {
	DeletedRegion   SarifRegion `json:"deletedRegion"`
	InsertedContent FixContent  `json:"insertedContent,omitempty"`
}

type FixContent struct {
	Text string `json:"text"`
}

type FixMessage struct {
	Text string `json:"text"`
}

type SarifRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}
