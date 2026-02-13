package logger

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func FromContext(ctx context.Context) zerolog.Logger {
	if l := log.Ctx(ctx); l != nil {
		return *l
	}
	return log.Logger
}
