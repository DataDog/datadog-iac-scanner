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
	IgnorePlatforms []string
	OnlyPlatforms   []string
}

// IacRuleConfig holds per-rule overrides: path scoping and severity override.
// nil slices mean "no restriction". A nil Severity means "no override".
type IacRuleConfig struct {
	IgnorePaths []string
	OnlyPaths   []string
	Severity    *string
}
