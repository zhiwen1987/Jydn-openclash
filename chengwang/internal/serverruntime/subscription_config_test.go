package serverruntime

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func subscriptionConfigFixture(t *testing.T) Config {
	t.Helper()
	c := runtimeD9Config(t)
	c.SubscriptionsEnabled = true
	c.IdentitiesFile = filepath.Join(c.DataDir, "identities.json")
	c.TLSCertFile = filepath.Join(c.DataDir, "tls.pem")
	c.TLSKeyFile = filepath.Join(c.DataDir, "tls-key.pem")
	return c
}
func subscriptionClearEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CHENGWANG_SUBSCRIPTIONS_ENABLED", "CHENGWANG_SUBSCRIPTION_WRITES_ENABLED", "CHENGWANG_SUBSCRIPTION_REFRESH_ENABLED", "CHENGWANG_SUBSCRIPTION_REFRESH_IDENTITY_ID", "CHENGWANG_SUBSCRIPTION_POLICY_FILE", "CHENGWANG_MANAGEMENT_TENANT_ID", "CHENGWANG_MANAGEMENT_SITE_ID", "CHENGWANG_MANAGEMENT_OBJECT_ID", "CHENGWANG_IDENTITIES_FILE", "CHENGWANG_TLS_CERT_FILE", "CHENGWANG_TLS_KEY_FILE", "CHENGWANG_MODE"} {
		t.Setenv(name, "")
	}
}
func TestServerRuntimeP205DisabledDefaultsAndResidualClosed(t *testing.T) {
	if validateSubscriptionConfig(Config{}) != nil {
		t.Fatal("disabled defaults")
	}
	for _, c := range []Config{{SubscriptionWritesEnabled: true}, {SubscriptionPolicyFile: "private-sentinel-path"}, {SubscriptionRefreshEnabled: true}, {SubscriptionRefreshIdentityID: "refresh-machine"}} {
		if validateSubscriptionConfig(c) == nil {
			t.Fatal("disabled residual subscription inputs")
		}
	}
}
func TestServerRuntimeP205IdentityTLSAndScopeRequired(t *testing.T) {
	c := subscriptionConfigFixture(t)
	if validateSubscriptionConfig(c) != nil {
		t.Fatal("complete local admission config")
	}
	for _, edit := range []func(*Config){func(c *Config) { c.IdentitiesFile = "" }, func(c *Config) { c.TLSCertFile = "" }, func(c *Config) { c.TLSKeyFile = "" }, func(c *Config) { c.TenantID = "" }, func(c *Config) { c.SiteID = "" }, func(c *Config) { c.Mode = "" }, func(c *Config) { c.ManagementObjectID = "" }} {
		bad := c
		edit(&bad)
		if validateSubscriptionConfig(bad) == nil {
			t.Fatal("partial subscription config")
		}
	}
}
func TestServerRuntimeP205PolicyPathIsCanonical(t *testing.T) {
	c := subscriptionConfigFixture(t)
	c.SubscriptionPolicyFile = filepath.Join(c.DataDir, "policy.json")
	if validateSubscriptionConfig(c) != nil {
		t.Fatal("canonical policy path")
	}
	for _, path := range []string{"relative.json", " " + c.SubscriptionPolicyFile, c.SubscriptionPolicyFile + " ", string(filepath.Separator), c.SubscriptionPolicyFile + string(filepath.Separator) + "..", c.SubscriptionPolicyFile + "\x00"} {
		c.SubscriptionPolicyFile = path
		if validateSubscriptionConfig(c) == nil {
			t.Fatal("unsafe policy path")
		}
	}
}
func TestServerRuntimeP205EnvironmentBooleanIsStrict(t *testing.T) {
	subscriptionClearEnvironment(t)
	for _, name := range []string{"CHENGWANG_SUBSCRIPTIONS_ENABLED", "CHENGWANG_SUBSCRIPTION_WRITES_ENABLED", "CHENGWANG_SUBSCRIPTION_REFRESH_ENABLED"} {
		for _, value := range []string{"TRUE", " true", "false ", "1", "yes", "private-sentinel"} {
			t.Setenv(name, value)
			if _, err := ConfigFromEnvironment(); err == nil || strings.Contains(err.Error(), value) {
				t.Fatal("invalid subscription gate accepted or echoed")
			}
			t.Setenv(name, "")
		}
	}
}

func TestServerRuntimeP207ARefreshRequiresIndependentClosedGates(t *testing.T) {
	c := subscriptionConfigFixture(t)
	c.SubscriptionWritesEnabled = true
	c.SubscriptionPolicyFile = filepath.Join(c.DataDir, "policy.json")
	c.SubscriptionRefreshEnabled = true
	c.SubscriptionRefreshIdentityID = "subscription-refresh-machine"
	if validateSubscriptionConfig(c) != nil {
		t.Fatal("complete refresh configuration rejected")
	}
	for _, edit := range []func(*Config){
		func(value *Config) { value.SubscriptionWritesEnabled = false },
		func(value *Config) { value.SubscriptionPolicyFile = "" },
		func(value *Config) { value.SubscriptionRefreshIdentityID = "" },
		func(value *Config) { value.SubscriptionRefreshIdentityID = "bad/identity" },
	} {
		bad := c
		edit(&bad)
		if validateSubscriptionConfig(bad) == nil {
			t.Fatal("partial refresh configuration accepted")
		}
	}
	c.SubscriptionRefreshEnabled = false
	if validateSubscriptionConfig(c) == nil {
		t.Fatal("disabled refresh retained machine identity")
	}
}
func TestServerRuntimeP205EnvironmentCompleteAndIndependent(t *testing.T) {
	subscriptionClearEnvironment(t)
	c := subscriptionConfigFixture(t)
	for name, value := range map[string]string{"CHENGWANG_SUBSCRIPTIONS_ENABLED": "true", "CHENGWANG_SUBSCRIPTION_WRITES_ENABLED": "false", "CHENGWANG_MANAGEMENT_TENANT_ID": c.TenantID, "CHENGWANG_MANAGEMENT_SITE_ID": c.SiteID, "CHENGWANG_MANAGEMENT_OBJECT_ID": c.ManagementObjectID, "CHENGWANG_MODE": c.Mode, "CHENGWANG_IDENTITIES_FILE": c.IdentitiesFile, "CHENGWANG_TLS_CERT_FILE": c.TLSCertFile, "CHENGWANG_TLS_KEY_FILE": c.TLSKeyFile} {
		t.Setenv(name, value)
	}
	got, err := ConfigFromEnvironment()
	if err != nil || !got.SubscriptionsEnabled || got.SubscriptionWritesEnabled || got.OperationWritesEnabled {
		t.Fatal("independent subscription config")
	}
}
func TestServerRuntimeP205ShortWriteTimeoutFailsBeforePrivateRead(t *testing.T) {
	c := subscriptionConfigFixture(t)
	called := false
	err := RunWith(Options{Config: &c, Context: context.Background(), ShutdownTimeout: time.Second, WriteTimeout: 15 * time.Second, Listen: func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("listener must not run")
	}})
	if err == nil || called || strings.Contains(err.Error(), c.IdentitiesFile) {
		t.Fatal("short response budget reached private identity or listener")
	}
}
func TestServerRuntimeP205PolicyOptionalForManualAdmissionOnly(t *testing.T) {
	c := subscriptionConfigFixture(t)
	if c.SubscriptionPolicyFile != "" || validateSubscriptionConfig(c) != nil {
		t.Fatal("manual admission requires no remote policy")
	}
	c.SubscriptionWritesEnabled = true
	if validateSubscriptionConfig(c) != nil {
		t.Fatal("independent manual write gate")
	}
}
func TestServerRuntimeP205ScopeNeverTruncatedOrHashed(t *testing.T) {
	c := subscriptionConfigFixture(t)
	for _, value := range []string{strings.Repeat("a", 65), "tenant@example", "site/path", " environment", "env\x00"} {
		bad := c
		bad.TenantID = value
		if validateSubscriptionConfig(bad) == nil || bad.TenantID != value {
			t.Fatal("incompatible scope silently rewritten")
		}
	}
}
