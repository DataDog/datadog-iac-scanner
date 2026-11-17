package docker

import (
	"path"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/parser/shell"
)

// NumberValue carries a numeric Dockerfile fact without turning a dynamic or
// malformed source value into a concrete number.
type NumberValue struct {
	Known bool  `json:"known"`
	Value int64 `json:"value"`
}

// Port is one EXPOSE declaration. A range has distinct start and end values;
// a single port uses the same value for both.
type Port struct {
	Start NumberValue `json:"start"`
	End   NumberValue `json:"end"`
}

func exposePorts(values []shell.Value) []Port {
	ports := make([]Port, 0, len(values))
	for i := range values {
		ports = append(ports, parseExposePort(&values[i]))
	}
	return ports
}

func parseExposePort(value *shell.Value) Port {
	unknown := Port{}
	if !value.Known {
		return unknown
	}
	port := value.Text
	if before, protocol, found := strings.Cut(port, "/"); found {
		if protocol == "" || strings.Contains(protocol, "/") {
			return unknown
		}
		port = before
	}
	startText, endText, isRange := strings.Cut(port, "-")
	start, startOK := parsePortNumber(startText)
	end, endOK := start, startOK
	if isRange {
		end, endOK = parsePortNumber(endText)
	}
	return Port{Start: NumberValue{Known: startOK, Value: start}, End: NumberValue{Known: endOK, Value: end}}
}

func parsePortNumber(raw string) (int64, bool) {
	value, err := strconv.ParseInt(raw, 10, 64)
	return value, err == nil
}

func userName(user *shell.Value) *shell.Value {
	if user == nil {
		return nil
	}
	name := *user
	if name.Known {
		name.Text, _, _ = strings.Cut(name.Text, ":")
	}
	if name.Default != nil {
		username, _, _ := strings.Cut(*name.Default, ":")
		name.Default = &username
	}
	return &name
}

func imageNamespace(repository string) string {
	first, _, _ := strings.Cut(path.Clean(repository), "/")
	if first == "." {
		return ""
	}
	return first
}

func copyFromKind(from *shell.Value) *shell.Value {
	if from == nil {
		return nil
	}
	kind := *from
	kind.Default = nil
	if from.Known {
		kind.Text = "name"
		if from.Text != "" && allDigits(from.Text) {
			kind.Text = "index"
		}
		kind.Raw = ""
		kind.Pattern = ""
		kind.References = nil
	}
	return &kind
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
