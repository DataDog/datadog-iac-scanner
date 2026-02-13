/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package model

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	remediationsHelper "github.com/DataDog/datadog-iac-scanner/pkg/report/remediations"
	"github.com/google/uuid"
)

var severityLevelEquivalence = map[model.Severity]string{
	"INFO":     "none",
	"LOW":      "none",
	"MEDIUM":   "note",
	"HIGH":     "warning",
	"CRITICAL": "error",
}

type sarifProperties map[string]interface{}

type ruleMetadata struct {
	queryID          string
	queryName        string
	queryDescription string
	queryURI         string
	queryCategory    string
	queryCwe         string
	queryPlatform    string
	queryProvider    string
	severity         model.Severity
	frameworks       []model.Framework
}

type ruleCISMetadata struct {
	descriptionText string
	id              string
	title           string
}

type sarifMessage struct {
	Text              string          `json:"text"`
	MessageProperties sarifProperties `json:"properties,omitempty"`
}

type sarifComponentReference struct {
	ComponentReferenceName  string `json:"name,omitempty"`
	ComponentReferenceGUID  string `json:"guid,omitempty"`
	ComponentReferenceIndex int    `json:"index,omitempty"`
}

type sarifDescriptorReference struct {
	ReferenceID    string                  `json:"id,omitempty"`
	ReferenceGUID  string                  `json:"guid,omitempty"`
	ReferenceIndex int                     `json:"index,omitempty"`
	ToolComponent  sarifComponentReference `json:"toolComponent,omitempty"`
}

type cweMessage struct {
	Text string `json:"text"`
}

type cweCsv struct {
	CweID            string     `json:"id"`
	FullDescription  cweMessage `json:"fullDescription"`
	ShortDescription cweMessage `json:"shortDescription"`
	GUID             string     `json:"guid"`
	HelpURI          string     `json:"helpUri"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifRelationship struct {
	Relationship sarifDescriptorReference `json:"target,omitempty"`
}

type sarifRule struct {
	RuleID               string              `json:"id"`
	RuleName             string              `json:"name"`
	RuleShortDescription sarifMessage        `json:"shortDescription"`
	RuleFullDescription  sarifMessage        `json:"fullDescription"`
	DefaultConfiguration sarifConfiguration  `json:"defaultConfiguration"`
	HelpURI              string              `json:"helpUri"`
	Relationships        []sarifRelationship `json:"relationships,omitempty"`
	RuleProperties       sarifProperties     `json:"properties,omitempty"`
}

type sarifDriver struct {
	ToolName     string              `json:"name"`
	ToolVersion  string              `json:"version"`
	ToolFullName string              `json:"fullName"`
	ToolURI      string              `json:"informationUri"`
	Properties   sarifToolProperties `json:"properties"`
	Rules        []sarifRule         `json:"rules"`
}

type sarifToolProperties struct {
	Tags []string `json:"tags"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifArtifactLocation struct {
	ArtifactURI string `json:"uri"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           model.SarifRegion     `json:"region"`
}

type SarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResult struct {
	ResultRuleID        string                   `json:"ruleId"`
	ResultRuleIndex     int                      `json:"ruleIndex"`
	ResultKind          string                   `json:"kind,omitempty"`
	ResultMessage       sarifMessage             `json:"message"`
	ResultLocations     []SarifLocation          `json:"locations"`
	PartialFingerprints SarifPartialFingerprints `json:"partialFingerprints,omitempty"`
	ResultLevel         string                   `json:"level"`
	ResultProperties    sarifProperties          `json:"properties,omitempty"`
	ResultFixes         []model.SarifFix         `json:"fixes,omitempty"`
}

type SarifPartialFingerprints struct {
	Sha                string `json:"SHA,omitempty"`
	DatadogFingerprint string `json:"DATADOG_FINGERPRINT,omitempty"`
	CommitSha          string `json:"commitSha,omitempty"`
	Email              string `json:"email,omitempty"`
	Author             string `json:"author,omitempty"`
	Date               string `json:"date,omitempty"`
	CommitMessage      string `json:"commitMessage,omitempty"`
}

type taxonomyDefinitions struct {
	DefinitionGUID             string     `json:"guid,omitempty"`
	DefinitionName             string     `json:"name,omitempty"`
	DefinitionID               string     `json:"id"`
	DefinitionShortDescription cweMessage `json:"shortDescription"`
	DefinitionFullDescription  cweMessage `json:"fullDescription"`
	HelpURI                    string     `json:"helpUri,omitempty"`
}

type sarifTaxonomy struct {
	TaxonomyGUID                              string                `json:"guid"`
	TaxonomyName                              string                `json:"name"`
	TaxonomyFullDescription                   sarifMessage          `json:"fullDescription,omitempty"`
	TaxonomyShortDescription                  sarifMessage          `json:"shortDescription"`
	TaxonomyDownloadURI                       string                `json:"downloadUri,omitempty"`
	TaxonomyInformationURI                    string                `json:"informationUri,omitempty"`
	TaxonomyIsComprehensive                   bool                  `json:"isComprehensive,omitempty"`
	TaxonomyLanguage                          string                `json:"language,omitempty"`
	TaxonomyMinRequiredLocDataSemanticVersion string                `json:"minimumRequiredLocalizedDataSemanticVersion,omitempty"`
	TaxonomyOrganization                      string                `json:"organization,omitempty"`
	TaxonomyRealeaseDateUtc                   string                `json:"releaseDateUtc,omitempty"`
	TaxonomyDefinitions                       []taxonomyDefinitions `json:"taxa"`
}

// SarifRun - sarifRun is a component of the SARIF report
type SarifRun struct {
	Tool       sarifTool       `json:"tool"`
	Results    []sarifResult   `json:"results"`
	Taxonomies []sarifTaxonomy `json:"taxonomies,omitempty"`
}

// SarifReport represents a usable sarif report reference
type SarifReport interface {
	BuildSarifIssue(ctx context.Context, issue *model.QueryResult, sciInfo model.SCIInfo) string
	RebuildTaxonomies(cwes []string, guids map[string]string)
	GetGUIDFromRelationships(idx int, cweID string) string
	AddTags(ctx context.Context, summary *model.Summary, diffAware *model.DiffAware) error
	ResolveFilepaths(basePath string) error
	SetToolVersionType(ctx context.Context, runType string)
}

type sarifReport struct {
	Schema       string     `json:"$schema"`
	SarifVersion string     `json:"version"`
	Runs         []SarifRun `json:"runs"`
}

const (
	diffAwareConfigDigestTag = "DATADOG_DIFF_AWARE_CONFIG_DIGEST:%s"
	diffAwareEnabledTag      = "DATADOG_DIFF_AWARE_ENABLED:%v"
	diffAwareBaseShaTag      = "DATADOG_DIFF_AWARE_BASE_SHA:%s"
	diffAwareFileTag         = "DATADOG_DIFF_AWARE_FILE:%s"
	executionTimeTag         = "DATADOG_EXECUTION_TIME_SECS:%v"
	ruleTypeProperty         = "DATADOG_RULE_TYPE:IAC_SCANNING"
	categoryTag              = "DATADOG_CATEGORY:%s"
	platformTag              = "DATADOG_PLATFORM:%s"
	providerTag              = "DATADOG_PROVIDER:%s"
	scannedFileCountTag      = "DATADOG_SCANNED_FILE_COUNT:%d"
)

func initSarifTool() sarifTool {
	return sarifTool{
		Driver: sarifDriver{
			// DO NOT CHANGE THIS VALUE. This value is needed for downstream mappings that rely on this value being "Datadog IaC Scanning"
			ToolName:     "Datadog IaC Scanning",
			ToolVersion:  constants.Version,
			ToolFullName: constants.Fullname,
			ToolURI:      constants.URL,
			Rules:        make([]sarifRule, 0),
		},
	}
}

// initCweCategories is responsible for building the CWE taxa field, inside taxonomies
func initCweCategories(cweIDs []string, guids map[string]string) []taxonomyDefinitions {
	absPath, err := filepath.Abs(".")
	if err != nil {
		return []taxonomyDefinitions{}
	}

	cweCSVPath := filepath.Join(absPath, "assets", "cwe_csv", "Software-Development-CWE.csv")
	cweCsvList, err := readCWECsvInfo(cweCSVPath)
	if err != nil {
		return []taxonomyDefinitions{}
	}

	var taxonomyList []taxonomyDefinitions
	for _, cweID := range cweIDs {
		var matchingCweEntry cweCsv

		for _, cweEntry := range cweCsvList {
			if cweEntry.CweID == cweID {
				matchingCweEntry = cweEntry
				break
			}
		}

		if matchingCweEntry.CweID == "" {
			continue
		}

		guid, exists := guids[cweID]
		if !exists {
			continue
		}

		taxonomy := taxonomyDefinitions{
			DefinitionID:               matchingCweEntry.CweID,
			DefinitionGUID:             guid,
			DefinitionFullDescription:  matchingCweEntry.FullDescription,
			DefinitionShortDescription: matchingCweEntry.ShortDescription,
			HelpURI:                    matchingCweEntry.HelpURI,
		}
		taxonomyList = append(taxonomyList, taxonomy)
	}

	return taxonomyList
}

func initSarifRun() []SarifRun {
	return []SarifRun{
		{
			Tool:    initSarifTool(),
			Results: make([]sarifResult, 0),
			// Taxonomies: initSarifTaxonomies(),
		},
	}
}

// NewSarifReport creates and start a new sarif report with default values respecting SARIF schema 2.1.0
func NewSarifReport() SarifReport {
	return &sarifReport{
		Schema:       "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		SarifVersion: "2.1.0",
		Runs:         initSarifRun(),
	}
}

func generateGUID() string {
	id := uuid.New()
	return id.String()
}

// readCWECsvInfo is responsible for reading the CWE taxonomy info from the corresponding csv file
func readCWECsvInfo(filePath string) ([]cweCsv, error) {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Note: -1 means records may have a variable number of fields in the csv file
	records, err := reader.ReadAll()

	if err != nil {
		return nil, err
	}

	var cweEntries []cweCsv
	numRecords := 23

	for _, record := range records {
		if len(record) >= numRecords {
			cweEntry := cweCsv{
				CweID: record[0],
				FullDescription: cweMessage{
					Text: record[5],
				},
				ShortDescription: cweMessage{
					Text: record[4],
				},
				GUID:    generateGUID(),
				HelpURI: "https://cwe.mitre.org/data/definitions/" + record[0] + ".html",
			}

			// Check if Extended Description is empty, fill it with Description if so
			if cweEntry.FullDescription.Text == "" {
				cweEntry.FullDescription.Text = record[4]
			}

			cweEntries = append(cweEntries, cweEntry)
		}
	}

	return cweEntries, nil
}

func (sr *sarifReport) findSarifRuleIndex(ruleID string) int {
	for idx := range sr.Runs[0].Tool.Driver.Rules {
		if sr.Runs[0].Tool.Driver.Rules[idx].RuleID == ruleID {
			return idx
		}
	}
	return -1
}

func (sr *sarifReport) buildSarifRule(queryMetadata *ruleMetadata, cisMetadata ruleCISMetadata) int {
	index := sr.findSarifRuleIndex(queryMetadata.queryID)

	if index < 0 {
		helpURI := "https://docs.datadoghq.com/security/code_security/iac_security/"
		if queryMetadata.queryURI != "" {
			helpURI = queryMetadata.queryURI
		}

		tags := []string{ruleTypeProperty}
		cwe := queryMetadata.queryCwe
		if cwe != "" {
			cweTag := GetCWETag(cwe)
			tags = append(tags, cweTag)
		}

		categoryTag := GetCategoryTag(queryMetadata.queryCategory)
		kicsRuleIDTag := GetKICSRuleIDTag(queryMetadata.queryID)
		platformTag := GetPlatformTag(queryMetadata.queryPlatform)
		providerTag := GetProviderTag(queryMetadata.queryProvider)
		tags = append(tags, categoryTag, kicsRuleIDTag, platformTag, providerTag)

		rule := sarifRule{
			RuleID:               queryMetadata.queryName,
			RuleName:             queryMetadata.queryName,
			RuleShortDescription: sarifMessage{Text: queryMetadata.queryName},
			RuleFullDescription:  sarifMessage{Text: fmt.Sprintf("%s\nRule ID: [%s]", queryMetadata.queryDescription, queryMetadata.queryID)},
			DefaultConfiguration: sarifConfiguration{Level: severityLevelEquivalence[queryMetadata.severity]},
			// Relationships:        relationships,
			HelpURI: helpURI,
			RuleProperties: sarifProperties{
				"tags":           tags,
				"iac-frameworks": queryMetadata.frameworks,
			},
		}
		if cisMetadata.id != "" {
			rule.RuleFullDescription.Text = cisMetadata.descriptionText
			rule.RuleProperties = sarifProperties{
				"cisId":    cisMetadata.id,
				"cisTitle": cisMetadata.title,
			}
		}

		sr.Runs[0].Tool.Driver.Rules = append(sr.Runs[0].Tool.Driver.Rules, rule)
		index = len(sr.Runs[0].Tool.Driver.Rules) - 1
	}
	return index
}

// GetGUIDFromRelationships gets the GUID from the relationship for each CWE item
func (sr *sarifReport) GetGUIDFromRelationships(idx int, cweID string) string {
	if len(sr.Runs) > 0 {
		if len(sr.Runs[0].Tool.Driver.Rules) > 0 {
			relationships := sr.Runs[0].Tool.Driver.Rules[idx].Relationships
			for _, relationship := range relationships {
				target := relationship.Relationship

				if target.ReferenceID == cweID {
					return target.ReferenceGUID
				}
			}
		}
	}

	return ""
}

// RebuildTaxonomies builds the taxonomies with the CWEs and the GUIDs coming from each relationships field
func (sr *sarifReport) RebuildTaxonomies(cwes []string, guids map[string]string) {
	if len(cwes) > 0 {
		result := initCweCategories(cwes, guids)
		if len(sr.Runs) > 0 {
			if len(sr.Runs[0].Taxonomies) == 2 {
				sr.Runs[0].Taxonomies[1].TaxonomyDefinitions = result
			}
		}
	}
}

// BuildSarifIssue creates a new entries in Results (one for each file) and new entry in Rules and Taxonomy if necessary
// nolint:gocritic
func (sr *sarifReport) BuildSarifIssue(ctx context.Context, issue *model.QueryResult, sciInfo model.SCIInfo) string {
	contextLogger := logger.FromContext(ctx)
	if len(issue.Files) > 0 {
		metadata := ruleMetadata{
			queryID:          issue.QueryID,
			queryName:        issue.QueryName,
			queryDescription: issue.Description,
			queryURI:         issue.QueryURI,
			queryCategory:    issue.Category,
			queryCwe:         issue.CWE,
			queryPlatform:    issue.Platform,
			queryProvider:    issue.CloudProvider,
			severity:         issue.Severity,
			frameworks:       issue.Frameworks,
		}
		cisDescriptions := ruleCISMetadata{
			id:              issue.CISDescriptionIDFormatted,
			title:           issue.CISDescriptionTitle,
			descriptionText: issue.CISDescriptionTextFormatted,
		}
		ruleIndex := sr.buildSarifRule(&metadata, cisDescriptions)

		categoryTag := GetCategoryTag(issue.Category)
		tags := []string{categoryTag}
		cwe := issue.CWE
		if cwe != "" {
			cweTag := GetCWETag(cwe)
			tags = append(tags, cweTag)
		}

		for idx := range issue.Files {
			vulnerability := issue.Files[idx]

			resourceType := vulnerability.ResourceType
			resourceName := vulnerability.ResourceName
			resourceTypeTag := GetResourceTypeTag(resourceType)
			resourceNameTag := GetResourceNameTag(resourceName)

			// nolint:gocritic
			resultTags := append(tags, resourceTypeTag, resourceNameTag)

			resourceLocation := vulnerability.ResourceLocation

			if resourceLocation.Start.Line < 1 || resourceLocation.End.Line < 1 {
				contextLogger.Warn().Msgf("Invalid resource location for file %s", issue.Files[idx].FileName)
				continue
			}

			if resourceLocation.Start.Col < 1 {
				resourceLocation.Start.Col = 1
			}
			if resourceLocation.End.Col < 1 {
				resourceLocation.End.Col = resourceLocation.Start.Col
			}

			resourceStartLocation := model.SarifResourceLocation{
				Line: resourceLocation.Start.Line,
				Col:  resourceLocation.Start.Col,
			}
			resourceEndLocation := model.SarifResourceLocation{
				Line: resourceLocation.End.Line,
				Col:  resourceLocation.End.Col,
			}

			remediationLocation := vulnerability.RemediationLocation
			remediationStartLocation := model.SarifResourceLocation{
				Line: remediationLocation.Start.Line,
				Col:  remediationLocation.Start.Col,
			}
			remediationEndLocation := model.SarifResourceLocation{
				Line: remediationLocation.End.Line,
				Col:  remediationLocation.End.Col,
			}

			if resourceStartLocation.Col < 1 {
				resourceStartLocation.Col = 1
			}

			if remediationStartLocation.Line >= resourceStartLocation.Line && remediationEndLocation.Line <= resourceEndLocation.Line {
				resourceStartLocation = remediationStartLocation
				resourceEndLocation = remediationEndLocation
			}

			absoluteFilePath := strings.ReplaceAll(issue.Files[idx].FileName, "../", "")
			result := sarifResult{
				ResultRuleID:    issue.QueryName,
				ResultRuleIndex: ruleIndex,
				ResultLevel:     severityLevelEquivalence[issue.Severity],
				ResultMessage: sarifMessage{
					Text: issue.Files[idx].KeyActualValue,
				},
				ResultLocations: []SarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: sarifArtifactLocation{ArtifactURI: absoluteFilePath},
							Region: model.SarifRegion{
								StartLine:   resourceStartLocation.Line,
								EndLine:     resourceEndLocation.Line,
								StartColumn: resourceStartLocation.Col,
								EndColumn:   resourceEndLocation.Col,
							},
						},
					},
				},
				ResultProperties: sarifProperties{
					"tags": resultTags,
				},
				PartialFingerprints: SarifPartialFingerprints{
					DatadogFingerprint: GetDatadogFingerprintHash(sciInfo, absoluteFilePath, resourceType, resourceName, issue.QueryID),
				},
			}
			if vulnerability.Remediation != "" && vulnerability.RemediationType != "" {
				sarifFix, err := remediationsHelper.TransformToSarifFix(
					ctx,
					vulnerability,
					remediationStartLocation,
					remediationEndLocation,
				)
				if err == nil {
					// we want the location displayed in the UI to properly highlight the remediation
					result.ResultLocations[0].PhysicalLocation.Region.StartLine = remediationStartLocation.Line
					result.ResultLocations[0].PhysicalLocation.Region.EndLine = remediationEndLocation.Line

					result.ResultFixes = append(result.ResultFixes, sarifFix)
				}
			}
			sr.Runs[0].Results = append(sr.Runs[0].Results, result)
		}
		return issue.CWE
	}
	return ""
}

func (sr *sarifReport) SetToolVersionType(ctx context.Context, runType string) {
	contextLogger := logger.FromContext(ctx)
	if runType != "" {
		for idx := range sr.Runs {
			sr.Runs[idx].Tool.Driver.ToolVersion = runType
		}
		contextLogger.Info().Msgf("Tool version set to %s", runType)
	}
}

func (sr *sarifReport) AddTags(ctx context.Context, summary *model.Summary, diffAware *model.DiffAware) error {
	contextLogger := logger.FromContext(ctx)
	if len(sr.Runs) != 1 {
		return errors.New("sarifReport must have exactly one run")
	}
	tagsToAppend := []string{}
	executionTimeTag := GetScanDurationTag(*summary)
	scannedFileCountTag := GetScannedFilesCountTag(summary.ScannedFiles)
	diffAwareEnabledTag := GetDiffAwareEnabledTag(*diffAware)

	tagsToAppend = append(tagsToAppend, executionTimeTag, scannedFileCountTag, diffAwareEnabledTag)

	if diffAware.Enabled {
		if diffAware.BaseSha == "" || diffAware.Files == "" || diffAware.ConfigDigest == "" {
			err := fmt.Errorf(
				"diffAware enabled but base sha %s, files %s, config digest %s provided",
				diffAware.BaseSha,
				diffAware.Files,
				diffAware.ConfigDigest,
			)
			contextLogger.Error().Msg(err.Error())
			return err
		}
		diffAwareConfigDigestTag := GetDiffAwareConfigDigestTag(*diffAware)
		diffAwareBaseShaTag := GetDiffAwareBaseShaTag(*diffAware)
		diffAwareFileTag := GetDiffAwareFilesTag(*diffAware)

		tagsToAppend = append(tagsToAppend, diffAwareConfigDigestTag, diffAwareBaseShaTag, diffAwareFileTag)
	}

	sarifToolProperties := &sr.Runs[0].Tool.Driver.Properties
	sarifToolProperties.Tags = append(
		sarifToolProperties.Tags,
		tagsToAppend...,
	)

	return nil
}

func (sr *sarifReport) ResolveFilepaths(basePath string) error {
	for idx := range sr.Runs[0].Results {
		artifactLocation := &sr.Runs[0].Results[idx].ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI
		resolvedLocation := strings.TrimPrefix(*artifactLocation, basePath+"/")
		sr.Runs[0].Results[idx].ResultLocations[0].PhysicalLocation.ArtifactLocation.ArtifactURI = resolvedLocation
	}
	return nil
}

// nolint:gocritic
func GetDatadogFingerprintHash(sciInfo model.SCIInfo, filePath, resourceType, resourceName, ruleId string) string {
	return StringToHash(fmt.Sprintf("%s|%s|%s|%s|%s", sciInfo.RepositoryCommitInfo.RepositoryUrl, filePath, resourceType, resourceName, ruleId)) //nolint:lll
}
