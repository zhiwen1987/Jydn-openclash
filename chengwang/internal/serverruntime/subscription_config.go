package serverruntime

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var errSubscriptionConfiguration = errors.New("subscription configuration is invalid")
var subscriptionRuntimeScopePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func validateSubscriptionConfig(c Config) error {
	if !c.SubscriptionsEnabled {
		if c.SubscriptionWritesEnabled || c.SubscriptionPolicyFile != "" {
			return errSubscriptionConfiguration
		}
		return nil
	}
	for _, value := range []string{c.TenantID, c.SiteID, c.Mode, c.ManagementObjectID} {
		if !subscriptionRuntimeScopePart.MatchString(value) {
			return errSubscriptionConfiguration
		}
	}
	if c.IdentitiesFile == "" || c.TLSCertFile == "" || c.TLSKeyFile == "" {
		return errSubscriptionConfiguration
	}
	if path := c.SubscriptionPolicyFile; path != "" {
		if strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || strings.ContainsRune(path, '\x00') {
			return errSubscriptionConfiguration
		}
	}
	return nil
}

func subscriptionConfigFromEnvironment(c *Config) error {
	var err error
	c.SubscriptionsEnabled, err = StrictBoolEnv("CHENGWANG_SUBSCRIPTIONS_ENABLED")
	if err != nil {
		return errSubscriptionConfiguration
	}
	c.SubscriptionWritesEnabled, err = StrictBoolEnv("CHENGWANG_SUBSCRIPTION_WRITES_ENABLED")
	if err != nil {
		return errSubscriptionConfiguration
	}
	c.SubscriptionPolicyFile = os.Getenv("CHENGWANG_SUBSCRIPTION_POLICY_FILE")
	return validateSubscriptionConfig(*c)
}
