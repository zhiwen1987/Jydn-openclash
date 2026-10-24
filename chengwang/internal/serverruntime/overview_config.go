package serverruntime

import "errors"

var errOverviewConfiguration = errors.New("live overview configuration is invalid")

// overviewConfigFromEnvironment only parses the opt-in flag. It never creates
// a provider, reads a cached status, or starts any worker. Assign only after
// successful parsing so a rejected environment cannot partially mutate c.
func overviewConfigFromEnvironment(c *Config) error {
	if c == nil {
		return errOverviewConfiguration
	}
	enabled, err := StrictBoolEnv("CHENGWANG_LIVE_OVERVIEW_ENABLED")
	if err != nil {
		return errOverviewConfiguration
	}
	c.LiveOverviewEnabled = enabled
	return nil
}
