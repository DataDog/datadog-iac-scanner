package logger

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type sensitiveError struct {
	secret string
}

func (e *sensitiveError) Error() string {
	return "invalid value: " + e.secret
}

func TestRedactError(t *testing.T) {
	require.NoError(t, RedactError(nil))
	original := &sensitiveError{secret: "synthetic-private-value"}
	err := RedactError(original)
	require.EqualError(t, err, "*logger.sensitiveError (details redacted)")
	require.ErrorIs(t, err, original)
	var cause *sensitiveError
	require.ErrorAs(t, err, &cause)
	require.Same(t, original, cause)
	require.Same(t, err, RedactError(err))

	wrapped := fmt.Errorf("invalid value synthetic-wrapper-value: %w", err)
	safeWrapped := RedactError(wrapped)
	require.NotContains(t, safeWrapped.Error(), "synthetic-wrapper-value")
	require.ErrorIs(t, safeWrapped, original)

	var logs bytes.Buffer
	log := zerolog.New(&logs)
	log.Error().Err(err).Msgf("parse failure: %v / %+v / %s", err, err, err)
	require.Contains(t, logs.String(), "details redacted")
	require.NotContains(t, logs.String(), original.secret)
}

type panickingError struct{}

func (*panickingError) Error() string {
	panic("untrusted Error method must not be called")
}

func TestRedactErrorDoesNotReadErrorText(t *testing.T) {
	// Includes a typed nil: even its Error method must never be evaluated.
	for _, original := range []error{&panickingError{}, (*panickingError)(nil)} {
		require.EqualError(t, RedactError(original), "*logger.panickingError (details redacted)")
	}
	// Redacting a wrapped error must not inspect its cause's Error method either.
	require.EqualError(t, RedactError(errors.Join(&panickingError{})), "*errors.joinError (details redacted)")
}

type sensitiveStringError string

func (e sensitiveStringError) Error() string {
	return string(e)
}

func TestRedactErrorProtectsGoSyntaxFormatting(t *testing.T) {
	const secret = "synthetic-private-string-error"
	err := RedactError(sensitiveStringError(secret))
	// Without GoString, %#v would traverse the wrapper and expose this value.
	formatted := fmt.Sprintf("%#v", err)
	require.Contains(t, formatted, "details redacted")
	require.NotContains(t, formatted, secret)
}
