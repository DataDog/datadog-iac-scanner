package featureflags

type LocalEvaluator struct {
	flags map[string]bool
}

func NewLocalEvaluatorWithOverrides(overrides map[string]bool) *LocalEvaluator {
	flags := map[string]bool{
		IacAttachCustomFrameworks:        true,
		IacAttachDefaultFrameworks:       true,
		IacDisableKicsRule:               false,
		IacEnableKicsPlatform:            true,
		IacEnableKicsHelmResolver:        true,
		IaCEnableKicsParallelFileParsing: true,
	}

	for k, v := range overrides {
		flags[k] = v
	}
	return &LocalEvaluator{
		flags: flags,
	}
}

func NewLocalEvaluator() *LocalEvaluator {
	return NewLocalEvaluatorWithOverrides(map[string]bool{})
}

func (l LocalEvaluator) Evaluate(flag string) bool {
	return l.flags[flag]
}

func (l LocalEvaluator) EvaluateWithOrg(flag string) bool {
	return l.flags[flag]
}

func (l LocalEvaluator) EvaluateWithEnv(flag string) bool {
	return l.flags[flag]
}

func (l LocalEvaluator) EvaluateWithOrgAndEnv(flag string) bool {
	return l.flags[flag]
}

func (l LocalEvaluator) EvaluateWithCustomVariables(flag string, variables map[string]interface{}) (bool, error) {
	return l.flags[flag], nil
}

func (l LocalEvaluator) EvaluateWithOrgAndCustomVariables(flag string, variables map[string]interface{}) (bool, error) {
	return l.flags[flag], nil
}

func (l LocalEvaluator) EvaluateWithEnvAndCustomVariables(flag string, variables map[string]interface{}) (bool, error) {
	return l.flags[flag], nil
}

func (l LocalEvaluator) EvaluateWithOrgAndEnvAndCustomVariables(flag string, variables map[string]interface{}) (bool, error) {
	return l.flags[flag], nil
}
