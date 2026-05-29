package config

type IacConfig struct {
	IgnoreRules      []string
	OnlyRules        []string
	IgnorePaths      []string
	OnlyPaths        []string
	IgnoreSeverities []string
	OnlySeverities   []string
	IgnoreCategories []string
	OnlyCategories   []string

	LegacyExcludeResults []string

	RuleConfigs     map[string]IacRuleConfig
	OnlyPlatforms   []string
	IgnorePlatforms []string
}

// IacRuleConfig holds per-rule overrides: path scoping and severity override.
// nil/empty slices mean "no restriction". An empty Severity means "no override".
type IacRuleConfig struct {
	IgnorePaths []string
	OnlyPaths   []string
	Severity    string // empty means no override
}
