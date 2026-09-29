package model

import "errors"

// PartialYAMLParseError reports a YAML stream with at least one usable document
// and at least one syntax or conversion failure. Only this error permits callers
// to retain returned documents; the file is still not a successful full parse.
type PartialYAMLParseError struct {
	Err error
}

func (e *PartialYAMLParseError) Error() string { return e.Err.Error() }
func (e *PartialYAMLParseError) Unwrap() error { return e.Err }

func IsPartialYAMLParseError(err error) bool {
	var partial *PartialYAMLParseError
	return errors.As(err, &partial)
}
