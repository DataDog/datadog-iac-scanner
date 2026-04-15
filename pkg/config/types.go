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
}
