package utils

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// CmdOutput stores the structure of the scanner output
type CmdOutput struct {
	Output []string
	Status int
}

const windowsOs = "windows"

// RunCommand executes the scanner in a terminal
func RunCommand(scannerArgs []string) (*CmdOutput, error) {
	program, args := runScannerDev(scannerArgs)

	cmd := exec.Command(program, args...) //#nosec
	stdOutput, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return &CmdOutput{
				Output: strings.Split(string(stdOutput), "\n"),
				Status: exitError.ExitCode(),
			}, nil
		}
		return &CmdOutput{}, err
	}
	return &CmdOutput{
		Output: strings.Split(string(stdOutput), "\n"),
		Status: 0,
	}, nil
}

// DevPathAdapter adapts the path to enable local scanner execution
func DevPathAdapter(path string) string {
	// [e2e-029] and [e2e-056] config tests
	switch path {
	case "/path/e2e/fixtures/samples/configs/config.json":
		path = strings.ReplaceAll(path, "config.json", "config-dev.json")
	case "/path/e2e/fixtures/samples/configs/config.yaml":
		path = strings.ReplaceAll(path, "config.yaml", "config-dev.yaml")
	}
	regex := regexp.MustCompile(`/path/\w+/`)
	matches := regex.FindString(path)
	switch matches {
	case "":
		return path
	case "/path/e2e/":
		return strings.ReplaceAll(path, matches, "")
	default:
		return strings.ReplaceAll(path, "/path/", "../")
	}
}

// GetScannerLocalBin returns the scanner local bin path
func GetScannerLocalBin() string {
	if runtime.GOOS == windowsOs {
		return filepath.Join("..", "bin", "datadog-iac-scanner.exe")
	}
	return filepath.Join("..", "bin", "datadog-iac-scanner")
}

func runScannerDev(scannerArgs []string) (bin string, args []string) {
	scannerBin := GetScannerLocalBin()
	var formatArgs []string
	for _, param := range scannerArgs {
		formatArgs = append(formatArgs, DevPathAdapter(param))
	}
	return scannerBin, formatArgs
}
