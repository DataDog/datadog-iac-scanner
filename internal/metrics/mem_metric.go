/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package metrics

import (
	"bytes"
	"runtime"
	"runtime/pprof"

	"github.com/rs/zerolog/log"
)

type memMetric struct {
	close   func()
	writer  *bytes.Buffer
	idx     int
	typeMap map[string]float64
}

const (
	b  = 1
	kb = 10
	mb = 20
	gb = 30
	tb = 40
	pb = 50
)

var memoryMap = map[string]float64{
	"B":  float64(b),
	"kB": float64(b << kb),
	"MB": float64(b << mb),
	"GB": float64(b << gb),
	"TB": float64(b << tb),
	"PB": float64(b << pb),
}

// Start - start gathering metrics for Memory usage
func (c *memMetric) start() {
	c.idx = 3 // inuse_space in the heap profile
	c.typeMap = memoryMap

	old := runtime.MemProfileRate
	runtime.MemProfileRate = 4096

	c.writer = bytes.NewBuffer([]byte{})
	c.close = func() {
		// Force a GC so inuse_space reflects live memory rather than uncollected
		// garbage at the moment the snapshot is taken.
		runtime.GC()
		if err := pprof.Lookup("heap").WriteTo(c.writer, 0); err != nil {
			log.Error().Msgf("failed to write mem profile")
		}
		runtime.MemProfileRate = old
	}
}

// Stop - stop gathering metrics for Memory usage. The collected buffer is
// written to a file by Metrics.writeProfile.
func (c *memMetric) stop() {
	c.close()
}

// getWriter returns the profile buffer
func (c *memMetric) getWriter() *bytes.Buffer {
	return c.writer
}

// getIndex returns the memory sample index
func (c *memMetric) getIndex() int {
	return c.idx
}

// getMap returns the map used to format total value
func (c *memMetric) getMap() map[string]float64 {
	return c.typeMap
}
