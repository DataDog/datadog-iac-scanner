package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var metadata Metadata = Metadata{
	Timestamp: time.RFC3339,
	Tools: &[]Tool{
		{
			Vendor:  "DataDog",
			Name:    "DataDog IaC Scanner",
			Version: constants.Version,
		},
	},
}

var initCycloneDxReport CycloneDxReport = CycloneDxReport{
	XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
	XMLNSV:       "http://cyclonedx.org/schema/ext/vulnerability/1.0",
	SerialNumber: "urn:uuid:", // set to "urn:uuid:" because it will be different for every report
	Version:      1,
	Metadata:     &metadata,
}

// TestInitCycloneDxReport tests the InitCycloneDxReport function
func TestInitCycloneDxReport(t *testing.T) {
	tests := []struct {
		name string
		want *CycloneDxReport
	}{
		{
			name: "Init CycloneDX report",
			want: &initCycloneDxReport,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InitCycloneDxReport()
			got.SerialNumber = "urn:uuid:"        // set to "urn:uuid:" because it will be different for every report
			got.Metadata.Timestamp = time.RFC3339 // set to a fixed time because of the nature of time
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitCycloneDxReport() = %v, want %v", got, tt.want)
			}
		})
	}
}

// fileSHA256 returns the hex-encoded SHA-256 of the file at path.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err, "could not read fixture %s", path)
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// retargetSummaryFiles deep-copies summary and rewrites every VulnerableFile
// name according to mapping. Deep-copying matters: the inputs are shared
// package-level mocks, and mutating them in place leaks across tests.
//
// Fails the test on any FileName absent from mapping. This guards against
// silent drift if the shared mocks in `test/helpers.go` change their fixture
// paths: instead of cyclonedx assertions failing with confusing path
// mismatches, we fail loudly here naming the unmapped key.
func retargetSummaryFiles(t *testing.T, in model.Summary, mapping map[string]string) model.Summary {
	t.Helper()
	out := in
	out.Queries = make([]model.QueryResult, len(in.Queries))
	for qi, q := range in.Queries {
		nq := q
		nq.Files = make([]model.VulnerableFile, len(q.Files))
		for fi, f := range q.Files {
			nf := f
			key := filepath.ToSlash(f.FileName)
			target, ok := mapping[key]
			if !ok {
				t.Fatalf("retargetSummaryFiles: mock FileName %q has no mapping entry; "+
					"shared mocks in test/helpers.go likely changed and this test needs an updated mapping", key)
			}
			nf.FileName = target
			nq.Files[fi] = nf
		}
		out.Queries[qi] = nq
	}
	return out
}

func TestBuildCycloneDxReport(t *testing.T) {
	// Use forward slashes deliberately: `BuildCycloneDxReport` normalizes
	// FileName via `strings.ReplaceAll(_, "\\", "/")` before building BomRef
	// / Purl, so the test must compare against slash form on every OS, and
	// Go's `os.ReadFile` accepts forward slashes on Windows.
	const (
		positivePath = "test/positive.tf"
		negativePath = "test/negative.tf"
		criticalPath = "test/critical_positive.yaml"
	)

	positiveSha := fileSHA256(t, positivePath)
	negativeSha := fileSHA256(t, negativePath)
	criticalSha := fileSHA256(t, criticalPath)

	purlFor := func(p, sha string) string {
		return fmt.Sprintf("pkg:generic/%s@0.0.0-%s", p, sha[0:12])
	}
	refFor := func(p, sha, id string) string {
		return fmt.Sprintf("pkg:generic/%s@0.0.0-%s%s", p, sha[0:12], id)
	}

	const (
		idInfo     = "e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10"
		idMedium   = "704dadd3-54fc-48ac-b6a0-02f170011473"
		idCritical = "316278b3-87ac-444c-8f8f-a733a28da609"
	)

	// vulnFor builds the subset of fields the assertions below actually compare
	// (Ref, ID, Source, Ratings, Description, Recommendations). Pass `cwe`
	// non-empty to set the optional CWE field.
	vulnFor := func(path, sha, id, severity, cwe, description, recommendation string) Vulnerability {
		return Vulnerability{
			Ref:             refFor(path, sha, id),
			ID:              id,
			CWE:             cwe,
			Source:          Source{Name: "DataDog IaC Scanner", URL: "https://www.datadoghq.com/"},
			Ratings:         []Rating{{Severity: severity, Method: "Other"}},
			Description:     description,
			Recommendations: []Recommendation{{Recommendation: recommendation}},
		}
	}

	const (
		descTags  = "[Terraform].[Resource Not Using Tags]: AWS services resource tags are an essential part of managing components"
		descGD    = "[Terraform].[GuardDuty Detector Disabled]: Make sure that Amazon GuardDuty is Enabled"
		descAMQ   = "[].[AmazonMQ Broker Encryption Disabled]: testCISDescription"
		recGDOn   = "Problem found in line 2."
		recAMQTLS = "Problem found in line 6."
	)
	recTagsFor := func(_ string) string {
		return "Problem found in line 1."
	}

	v1 := vulnFor(positivePath, positiveSha, idInfo, "None", "", descTags, recTagsFor("positive1"))
	v2 := vulnFor(positivePath, positiveSha, idMedium, "Medium", "", descGD, recGDOn)
	v3 := vulnFor(negativePath, negativeSha, idInfo, "None", "", descTags, recTagsFor("negative1"))
	v4 := vulnFor(negativePath, negativeSha, idMedium, "Medium", "22", descGD, recGDOn)
	v5 := vulnFor(criticalPath, criticalSha, idCritical, "Critical", "", descAMQ, recAMQTLS)

	componentFor := func(path, sha string, vulns []Vulnerability) Component {
		return Component{
			Type:    "file",
			BomRef:  purlFor(path, sha),
			Name:    path,
			Version: fmt.Sprintf("0.0.0-%s", sha[0:12]),
			Purl:    purlFor(path, sha),
			Hashes: []Hash{
				{Alg: "SHA-256", Content: sha},
			},
			Vulnerabilities: vulns,
		}
	}

	cyclonePositive := componentFor(positivePath, positiveSha, []Vulnerability{v1, v2})
	cycloneNegative := componentFor(negativePath, negativeSha, []Vulnerability{v3})
	cycloneCWENegative := componentFor(negativePath, negativeSha, []Vulnerability{v4})
	cycloneCritical := componentFor(criticalPath, criticalSha, []Vulnerability{v5})

	cycloneDx := initCycloneDxReport
	cycloneDx.Components.Components = append(cycloneDx.Components.Components, cycloneNegative, cyclonePositive)
	cycloneDxCWE := initCycloneDxReport
	cycloneDxCWE.Components.Components = append(cycloneDxCWE.Components.Components, cycloneCWENegative)
	cycloneDxCritical := initCycloneDxReport
	cycloneDxCritical.Components.Components = append(cycloneDxCritical.Components.Components, cycloneCritical)

	// Map the file names baked into the shared mocks to the local test
	// paths. Keyed on slash form because that's what filepath.ToSlash returns
	// on both Windows and Unix.
	mapping := map[string]string{
		filepath.ToSlash(filepath.Join("testdata", "guardduty_detector_disabled", "positive.tf")): positivePath,
		filepath.ToSlash(filepath.Join("testdata", "guardduty_detector_disabled", "negative.tf")): negativePath,
		filepath.ToSlash(filepath.Join("test", "fixtures", "test_critical_custom_queries", "amazon_mq_broker_encryption_disabled", "test", "positive1.yaml")): criticalPath,
	}

	summaryGuardduty := retargetSummaryFiles(t, test.ExampleSummaryMock, mapping)
	summaryCritical := retargetSummaryFiles(t, test.SummaryMockCritical, mapping)
	summaryCWE := retargetSummaryFiles(t, test.ExampleSummaryMockCWE, mapping)

	type args struct {
		summary   *model.Summary
		filePaths map[string]string
	}
	tests := []struct {
		name string
		args args
		want *CycloneDxReport
	}{
		{
			name: "Build CycloneDX report",
			args: args{
				summary:   &summaryGuardduty,
				filePaths: map[string]string{positivePath: positivePath, negativePath: negativePath},
			},
			want: &cycloneDx,
		},
		{
			name: "Build CycloneDX report with critical severity",
			args: args{
				summary:   &summaryCritical,
				filePaths: map[string]string{criticalPath: criticalPath},
			},
			want: &cycloneDxCritical,
		},
		{
			name: "Build CycloneDX report with cwe field complete",
			args: args{
				summary:   &summaryCWE,
				filePaths: map[string]string{negativePath: negativePath},
			},
			want: &cycloneDxCWE,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildCycloneDxReport(ctx, tt.args.summary, tt.args.filePaths)
			got.SerialNumber = "urn:uuid:" // set to "urn:uuid:" because it will be different for every report
			assert.Equal(t, len(tt.want.Components.Components), len(got.Components.Components), "Comparing number of components")
			for idx := range got.Components.Components {
				assert.Equal(t, tt.want.Components.Components[idx].BomRef, got.Components.Components[idx].BomRef, "Comparing BomRef of components")
				assert.Equal(t, tt.want.Components.Components[idx].Version, got.Components.Components[idx].Version, "Comparing Version of components")
				assert.Equal(t, tt.want.Components.Components[idx].Purl, got.Components.Components[idx].Purl, "Comparing Purl of components")
				assert.Equal(t, tt.want.Components.Components[idx].Hashes, got.Components.Components[idx].Hashes, "Comparing Hashes of components")
				for idx2 := range got.Components.Components[idx].Vulnerabilities {
					assert.Equal(t, tt.want.Components.Components[idx].Vulnerabilities[idx2].Ref, got.Components.Components[idx].Vulnerabilities[idx2].Ref, "Comparing Vulnerabilities Ref of components")
					assert.Equal(t, tt.want.Components.Components[idx].Vulnerabilities[idx2].Description, got.Components.Components[idx].Vulnerabilities[idx2].Description, "Comparing Vulnerabilities Description of components")
					assert.Equal(t, tt.want.Components.Components[idx].Vulnerabilities[idx2].Ratings, got.Components.Components[idx].Vulnerabilities[idx2].Ratings, "Comparing Vulnerabilities Ratings of components")
					assert.Equal(t, tt.want.Components.Components[idx].Vulnerabilities[idx2].Recommendations, got.Components.Components[idx].Vulnerabilities[idx2].Recommendations, "Comparing Vulnerabilities Recommendations of components")
				}
			}
		})
	}
}

