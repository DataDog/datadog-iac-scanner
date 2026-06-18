/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package metrics

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/google/pprof/profile"
	"github.com/rs/zerolog/log"
)

const (
	profileCPU = "cpu"
	profileMEM = "mem"
)

var (
	// Metric is the global metrics object
	Metric = &Metrics{
		Disable: true,
	}
)

// Start - starts gathering metrics based on the type of metrics and writes metrics to string
// Stop - stops gathering metrics for the type of metrics specified
type metricType interface {
	start()
	stop()
	getWriter() *bytes.Buffer
	getIndex() int
	getMap() map[string]float64
}

// Metrics - structure to keep information relevant to the metrics calculation
// Disable - disables metric calculations
type Metrics struct {
	metric    metricType
	metricsID string
	location  string
	Disable   bool
	total     int64

	// The global pprof profiler permits only one active profile at a time, so
	// Start/Stop are serialized and nested regions are subsumed by the
	// outermost one. mu guards depth and the start/stop transitions.
	mu    sync.Mutex
	depth int
}

// InitializeMetrics - creates a new instance of a Metrics based on the type of
// metrics specified.
func InitializeMetrics(metric string) error {
	Metric.total = 0
	Metric.depth = 0

	switch strings.ToLower(metric) {
	case profileCPU:
		Metric.metric = &cpuMetric{}
		Metric.metricsID = profileCPU
		Metric.Disable = false
	case profileMEM:
		// Set once before any allocation so pprof can treat the rate as constant
		// for the program lifetime, as the runtime docs require.
		runtime.MemProfileRate = 4096
		Metric.metric = &memMetric{}
		Metric.metricsID = profileMEM
		Metric.Disable = false
	case "":
		Metric.Disable = true
	default:
		Metric.Disable = true
		return fmt.Errorf("unknown metric: %s (available metrics: CPU, MEM)", metric)
	}

	return nil
}

// Start - starts gathering metrics for the location specified. A profile is only
// started for the outermost region; nested Start calls are counted so the
// matching Stop calls stay balanced but do not start a second profile.
func (m *Metrics) Start(location string) {
	if m.Disable {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.depth++
	if m.depth > 1 {
		log.Debug().Msgf("Skipping nested %s profiling for %s (already profiling %s)",
			m.metricsID, location, m.location)
		return
	}

	log.Debug().Msgf("Started %s profiling for %s", m.metricsID, location)
	m.location = location
	m.metric.start()
}

// Stop - stops gathering metrics and logs the result. Only the Stop that closes
// the outermost region finalizes the profile.
func (m *Metrics) Stop() {
	if m.Disable {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.depth == 0 {
		return // unbalanced Stop; nothing to finalize
	}
	m.depth--
	if m.depth > 0 {
		return // still inside an outer region
	}

	log.Debug().Msgf("Stopped %s profiling for %s", m.metricsID, m.location)
	m.metric.stop()
	m.writeProfile()

	p, err := profile.Parse(m.metric.getWriter())
	if err != nil {
		log.Error().Msgf("failed to parse profile on %s: %s", m.location, err)
		return
	}
	if err := p.CheckValid(); err != nil {
		log.Error().Msgf("invalid profile on %s: %s", m.location, err)
		return
	}

	total := getTotal(p, m.metric.getIndex())
	formatted := m.formatTotal(total, m.metric.getMap())
	// The MEM total is a whole-process live-heap snapshot taken when the phase
	// ends, not memory attributable to the phase alone, so word it as "live heap
	// after" rather than "usage for".
	if m.metricsID == profileMEM {
		log.Info().Msgf("Total MEM live heap after %s: %s", m.location, formatted)
	} else {
		log.Info().Msgf("Total %s usage for %s: %s", strings.ToUpper(m.metricsID), m.location, formatted)
	}
	m.total = total
}

// writeProfile writes the collected profile buffer to a file in the system temp
// dir so it can be inspected with `go tool pprof`.
func (m *Metrics) writeProfile() {
	f, err := os.CreateTemp("", fmt.Sprintf("iac-%s-*.prof", m.metricsID))
	if err != nil {
		log.Error().Msgf("failed to create %s profile file: %s", m.metricsID, err)
		return
	}
	name := f.Name()
	_, writeErr := f.Write(m.metric.getWriter().Bytes())
	closeErr := f.Close()
	if writeErr != nil {
		log.Error().Msgf("failed to write %s profile file: %s", m.metricsID, writeErr)
		return
	}
	if closeErr != nil {
		log.Error().Msgf("failed to close %s profile file: %s", m.metricsID, closeErr)
		return
	}
	log.Info().Msgf("%s profile written to %s — view with: go tool pprof %s", m.metricsID, name, name)
}

// getTotal sums the sample values at idx for the whole profile: the total CPU
// time for a CPU profile, or the live heap (inuse_space) for a MEM profile. Heap
// sample values are non-negative, so a plain sum is the process-wide total.
func getTotal(prof *profile.Profile, idx int) int64 {
	var total int64
	for _, sample := range prof.Sample {
		total += sample.Value[idx]
	}

	return total
}

// formatTotal parses total value into a human readable way
func (m *Metrics) formatTotal(b int64, typeMap map[string]float64) string {
	value := float64(b)
	var formatter float64
	var measure string
	for k, u := range typeMap {
		if u >= formatter && (value/u) >= 1.0 {
			formatter = u
			measure = k
		}
	}

	metric := value / formatter
	if math.IsNaN(metric) {
		metric = 0
	}

	return fmt.Sprintf("%.2f%s", metric, measure)
}
