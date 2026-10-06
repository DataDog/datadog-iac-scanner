/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package detector

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
)

// playbookLines builds a YAML playbook with n tasks, each named uniquely.
func playbookLines(n int) []string {
	lines := []string{"---", "- name: Example playbook", "  hosts: localhost", "  tasks:"}
	for i := 0; i < n; i++ {
		lines = append(lines,
			fmt.Sprintf("    - name: Install package %d", i),
			"      ansible.builtin.yum:",
			fmt.Sprintf("        name: pkg-%d", i),
			"        state: latest",
			"")
	}
	return lines
}

// scanByStr1 is the previous candidate selection: every line containing str1.
func scanByStr1(file *model.FileMetadata, str1, str2 string, lines []string, visits *int) int {
	candidates, _ := file.LinesContaining(str1)
	best, bestDistance := -1, 0
	for _, i := range candidates {
		*visits++
		distance, _, _, ok := checkLine(str1, str2, lines, i, model.KindYAML)
		if ok && (best < 0 || distance < bestDistance) {
			best, bestDistance = i, distance
		}
		if ok && distance == 0 {
			break
		}
	}
	return best
}

func TestCandidateSelectionVisitsFewerLines(t *testing.T) {
	file := &model.FileMetadata{OriginalData: strings.Join(playbookLines(1000), "\n")}
	file.SetLazyLines()
	lines := file.Lines()

	var oldVisits, newVisits int
	for _, task := range []int{0, 250, 500, 999} {
		str2 := fmt.Sprintf("Install package %d", task)
		var visits int
		want := scanByStr1(file, "name", str2, lines, &visits)
		oldVisits += visits

		first, second, ok := (&DefaultDetectLineResponse{File: file}).candidateLines("name", str2, model.KindYAML)
		if !ok {
			t.Fatal("expected cached candidates")
		}
		got := -1
		walkAscending(first, second, 0, func(i int) bool {
			newVisits++
			if _, _, _, matched := checkLine("name", str2, lines, i, model.KindYAML); matched {
				got = i
				return true
			}
			return false
		})
		if got != want {
			t.Fatalf("task %d: line %d, want %d", task, got, want)
		}
	}
	t.Logf("lines scored: previous %d, now %d", oldVisits, newVisits)
	if newVisits*20 > oldVisits {
		t.Fatalf("expected at least a 20x reduction, got %d vs %d", oldVisits, newVisits)
	}
}

func BenchmarkCandidateSelection(b *testing.B) {
	file := &model.FileMetadata{OriginalData: strings.Join(playbookLines(2000), "\n")}
	file.SetLazyLines()
	lines := file.Lines()
	str2s := make([]string, 0, 200)
	for i := 0; i < 2000; i += 10 {
		str2s = append(str2s, fmt.Sprintf("Install package %d", i))
	}
	b.Run("previous_by_str1", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			var visits int
			for _, s := range str2s {
				scanByStr1(file, "name", s, lines, &visits)
			}
		}
	})
	b.Run("current", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for _, s := range str2s {
				d := &DefaultDetectLineResponse{File: file}
				d.DetectCurrentLine("name", s, 0, lines, model.KindYAML)
			}
		}
	})
}
