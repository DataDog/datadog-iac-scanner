/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package report

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	reportModel "github.com/DataDog/datadog-iac-scanner/pkg/report/model"
	"github.com/gocarina/gocsv"
)

var (
	stringsSeverity = map[string]model.Severity{
		"critical": model.AllSeverities[0],
		"high":     model.AllSeverities[1],
		"medium":   model.AllSeverities[2],
		"low":      model.AllSeverities[3],
		"info":     model.AllSeverities[4],
	}

	templateFuncs = template.FuncMap{
		"lower":          strings.ToLower,
		"sprintf":        fmt.Sprintf,
		"severity":       getSeverities,
		"getCurrentTime": getCurrentTime,
		"trimSpaces":     trimSpaces,
		"toString":       toString,
	}
)

const filePerms = 0644

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func trimSpaces(value string) string {
	return strings.TrimPrefix(value, " ")
}

func getSeverities(severity string) model.Severity {
	return stringsSeverity[severity]
}

func getCurrentTime() string {
	dt := time.Now()
	return dt.Format("01/02/2006 15:04")
}

func fileCreationReport(ctx context.Context, path, filename string) {
	contextLogger := logger.FromContext(ctx)
	contextLogger.Info().Str("fileName", filename).Msgf("Results saved to file %s", path)
}

func closeFile(ctx context.Context, path, filename string, file *os.File) {
	contextLogger := logger.FromContext(ctx)
	err := file.Close()
	if err != nil {
		contextLogger.Err(err).Msgf("Failed to close file %s", path)
	}

	fileCreationReport(ctx, path, filename)
}

func getPlatforms(queries model.QueryResultSlice) string {
	platforms := make([]string, 0)
	alreadyAdded := make(map[string]string)
	for idx := range queries {
		if _, ok := alreadyAdded[queries[idx].Platform]; !ok {
			alreadyAdded[queries[idx].Platform] = ""
			platforms = append(platforms, queries[idx].Platform)
		}
	}
	return strings.Join(platforms, ", ")
}

// ExportJSONReport - encodes a given body to a JSON file in a given filepath
func ExportJSONReport(ctx context.Context, path, filename string, body interface{}) error {
	contextLogger := logger.FromContext(ctx)
	if !strings.Contains(filename, ".") {
		filename += jsonExtension
	}
	fullPath := filepath.Join(path, filename)

	f, err := os.OpenFile(filepath.Clean(fullPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerms)
	if err != nil {
		return err
	}

	defer closeFile(ctx, fullPath, filename, f)

	var minifiedJSON bytes.Buffer
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		contextLogger.Err(err).Msg("failed to marshal sarif report body: ")
		return err
	}

	err = json.Compact(&minifiedJSON, bodyBytes)
	if err != nil {
		contextLogger.Err(err).Msg("Error minifying JSON:")
		return err
	}

	_, err = f.Write(minifiedJSON.Bytes())

	return err
}

func getSummary(body interface{}) (sum model.Summary, err error) {
	var summary model.Summary
	result, err := json.Marshal(body)
	if err != nil {
		return model.Summary{}, err
	}
	if err := json.Unmarshal(result, &summary); err != nil {
		return model.Summary{}, err
	}

	return summary, nil
}

func exportXMLReport(ctx context.Context, path, filename string, body interface{}) error {
	contextLogger := logger.FromContext(ctx)
	if !strings.HasSuffix(filename, ".xml") {
		filename += ".xml"
	}

	fullPath := filepath.Join(path, filename)
	f, err := os.OpenFile(filepath.Clean(fullPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerms)
	if err != nil {
		return err
	}
	defer closeFile(ctx, fullPath, filename, f)
	if _, err = f.WriteString(xml.Header); err != nil {
		contextLogger.Debug().Err(err).Msg("Failed to write XML header")
	}
	encoder := xml.NewEncoder(f)
	encoder.Indent("", "\t")

	return encoder.Encode(body)
}

func exportCSVReport(ctx context.Context, path, filename string, body []reportModel.CSVReport) error {
	fullPath := filepath.Join(path, filename)
	f, err := os.OpenFile(filepath.Clean(fullPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerms)
	if err != nil {
		return err
	}

	defer closeFile(ctx, fullPath, filename, f)

	return gocsv.MarshalFile(&body, f)
}
