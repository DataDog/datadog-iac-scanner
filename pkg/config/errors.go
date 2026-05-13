package config

// InvalidLocalConfigError is returned when the local IaC configuration file
// cannot be read or parsed. It does NOT cover errors from remote config sources
// such as Datadog API calls via WithDatadog.
type InvalidLocalConfigError struct {
	err error
}

func newInvalidLocalConfigError(err error) error {
	return &InvalidLocalConfigError{err: err}
}

func (e *InvalidLocalConfigError) Error() string { return e.err.Error() }
func (e *InvalidLocalConfigError) Unwrap() error { return e.err }
