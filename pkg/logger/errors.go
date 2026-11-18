package logger

import "fmt"

// RedactError hides the text of an error derived from untrusted file content.
// Parsers and renderers can quote arbitrary credentials, so matching known
// secret formats is insufficient. Keep only the Go error type for diagnostics.
// The cause remains available to errors.Is/As for control flow; do not log it.
// Use this at shared parsing boundaries and for internal diagnostics emitted
// before those boundaries.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(*redactedError); ok {
		return err
	}
	return &redactedError{cause: err}
}

type redactedError struct {
	cause error
}

func (e *redactedError) Error() string {
	return fmt.Sprintf("%T (details redacted)", e.cause)
}

// GoString also protects diagnostic formatting with %#v from exposing the cause.
func (e *redactedError) GoString() string {
	return e.Error()
}

func (e *redactedError) Unwrap() error {
	return e.cause
}
