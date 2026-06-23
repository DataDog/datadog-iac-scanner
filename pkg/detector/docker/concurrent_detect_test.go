/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package docker

import (
	"context"
	"sync"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/utils"
)

// TestDockerDetect_ConcurrentSharedFile guards against in-place mutation of a
// shared *FileMetadata during line detection.
//
// Run with -race; the Dockerfile below uses line continuations to exercise the
// continuation-rewriting path.
func TestDockerDetect_ConcurrentSharedFile(t *testing.T) {
	const dockerfile = `FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/*
USER root
EXPOSE 22
CMD ["/bin/bash"]
`
	// One shared FileMetadata, as the inspector shares it across workers.
	file := &model.FileMetadata{
		FilePath:          "Dockerfile",
		Kind:              model.KindDOCKER,
		OriginalData:      dockerfile,
		LinesOriginalData: utils.SplitLines(dockerfile),
	}

	const (
		workers   = 32
		searchKey = "FROM={{ubuntu:20.04}}"
	)
	detector := DetectKindLine{}
	ctx := context.Background()

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		lineCounts = map[int]int{}
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := detector.DetectLine(ctx, file, searchKey, 3)
			mu.Lock()
			lineCounts[res.Line]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	// All concurrent calls must agree on the detected line; more than one
	// distinct result means the shared file buffer was mutated mid-detection.
	if len(lineCounts) != 1 {
		t.Errorf("non-deterministic detected line across %d concurrent calls on a shared file: %v",
			workers, lineCounts)
	}
}
