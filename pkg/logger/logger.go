package logger

import (
	"context"
	"io"
	stdlog "log"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func FromContext(ctx context.Context) zerolog.Logger {
	if l := log.Ctx(ctx); l != nil {
		return *l
	}
	return log.Logger
}

var (
	stdLogMu      sync.Mutex
	stdLogSilence int
	stdLogOutput  io.Writer
)

// SilenceStdLog discards the standard logger until the returned func runs.
// Helm and Kustomize renders write noise or secret values to it and run
// concurrently, so one reference count guards it: the logger is restored only
// when the last render ends, to the output it had before the first.
func SilenceStdLog() func() {
	stdLogMu.Lock()
	defer stdLogMu.Unlock()
	if stdLogSilence == 0 {
		stdLogOutput = stdlog.Writer()
		stdlog.SetOutput(io.Discard)
	}
	stdLogSilence++
	return func() {
		stdLogMu.Lock()
		defer stdLogMu.Unlock()
		stdLogSilence--
		if stdLogSilence == 0 {
			stdlog.SetOutput(stdLogOutput)
		}
	}
}
