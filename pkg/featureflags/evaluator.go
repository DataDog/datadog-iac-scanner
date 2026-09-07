package featureflags

const (
	IacAttachCustomFrameworks        = "k9-iac-attach-custom-frameworks"
	IacAttachDefaultFrameworks       = "k9-iac-attach-default-frameworks"
	IacDisableKicsRule               = "k9-iac-disable-kics-rule"
	IacEnableKicsPlatform            = "k9-iac-enable-kics-platform"
	IacEnableKicsHelmResolver        = "k9-iac-enable-kics-helm-resolver"
	IaCEnableKicsParallelFileParsing = "k9-iac-enable-kics-parallel-file-parsing"
)

type FlagEvaluator interface {
	Evaluate(flag string) bool
	EvaluateWithOrg(flag string) bool
	EvaluateWithEnv(flag string) bool
	EvaluateWithOrgAndEnv(flag string) bool
	EvaluateWithCustomVariables(flag string, variables map[string]interface{}) (bool, error)
	EvaluateWithOrgAndCustomVariables(flag string, variables map[string]interface{}) (bool, error)
	EvaluateWithEnvAndCustomVariables(flag string, variables map[string]interface{}) (bool, error)
	EvaluateWithOrgAndEnvAndCustomVariables(flag string, variables map[string]interface{}) (bool, error)
}
