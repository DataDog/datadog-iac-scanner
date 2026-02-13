/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package report

import (
	"bytes"
	"context"
	_ "embed" // used for embedding report static files
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/internal/constants"
	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/tdewolff/minify/v2"
	minifyCSS "github.com/tdewolff/minify/v2/css"
	minifyHtml "github.com/tdewolff/minify/v2/html"
	minifyJS "github.com/tdewolff/minify/v2/js"
)

var (
	//go:embed template/html/report.tmpl
	htmlTemplate string
	//go:embed template/html/report.css
	cssTemplate string
	//go:embed template/html/report.js
	jsTemplate string
	//go:embed template/html/github.svg
	githubSVG string
	//go:embed template/html/info.svg
	infoSVG string
	//go:embed template/html/vulnerability_fill.svg
	vulnerabilityFillSVG string
	//go:embed template/html/vulnerability_out.svg
	vulnerabilityOutSVG string
)

const htmlFilePerms = 0644

const (
	textHTML = "text/html"
)

var svgMap = map[string]string{
	"github.svg":             githubSVG,
	"info.svg":               infoSVG,
	"vulnerability_fill.svg": vulnerabilityFillSVG,
	"vulnerability_out.svg":  vulnerabilityOutSVG,
}

func includeSVG(name string) template.HTML {
	return template.HTML(svgMap[name]) //nolint
}

func includeCSS(name string) template.HTML {
	minifier := minify.New()
	minifier.AddFunc("text/css", minifyCSS.Minify)
	cssMinified, err := minifier.String("text/css", cssTemplate)
	if err != nil {
		return ""
	}
	return template.HTML("<style>" + cssMinified + "</style>") //nolint
}

func includeJS(name string) template.HTML {
	minifier := minify.New()
	minifier.AddFunc("text/javascript", minifyJS.Minify)
	jsMinified, err := minifier.String("text/javascript", jsTemplate)
	if err != nil {
		return ""
	}
	return template.HTML("<script>" + jsMinified + "</script>") //nolint
}

func getPaths(paths []string) string {
	return strings.Join(paths, ", ")
}

func getVersion() string {
	return constants.Version
}

// PrintHTMLReport creates a report file on HTML format
func PrintHTMLReport(ctx context.Context, path, filename string, body interface{}, sciInfo *model.SCIInfo) error {
	contextLogger := logger.FromContext(ctx)
	if !strings.HasSuffix(filename, ".html") {
		filename += ".html"
	}

	templateFuncs["includeSVG"] = includeSVG
	templateFuncs["includeCSS"] = includeCSS
	templateFuncs["includeJS"] = includeJS
	templateFuncs["getPaths"] = getPaths
	templateFuncs["getPlatforms"] = getPlatforms
	templateFuncs["getVersion"] = getVersion

	fullPath := filepath.Join(path, filename)
	t := template.Must(template.New("report.tmpl").Funcs(templateFuncs).Parse(htmlTemplate))

	f, err := os.OpenFile(filepath.Clean(fullPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, htmlFilePerms)
	if err != nil {
		return err
	}
	defer closeFile(ctx, fullPath, filename, f)
	var buffer bytes.Buffer

	err = t.Execute(&buffer, body)
	if err != nil {
		return err
	}
	minifier := minify.New()
	minifier.AddFunc(textHTML, minifyHtml.Minify)
	minifier.Add(textHTML, &minifyHtml.Minifier{
		KeepDocumentTags: true,
		KeepEndTags:      true,
		KeepQuotes:       true,
	})

	minifierWriter := minifier.Writer(textHTML, f)
	defer func() {
		if closeErr := minifierWriter.Close(); closeErr != nil {
			contextLogger.Err(closeErr).Msg("Error closing file")
		}
	}()

	_, err = minifierWriter.Write(buffer.Bytes())
	return err
}
