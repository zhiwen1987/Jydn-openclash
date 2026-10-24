package serverruntime

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestLiveOverviewEnvironmentDefaultsDisabled(t *testing.T) {
	const key = "CHENGWANG_LIVE_OVERVIEW_ENABLED"
	for _, name := range []string{"unset", "empty", "false"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(key, "")
			if name == "unset" {
				if err := os.Unsetenv(key); err != nil {
					t.Fatal("could not prepare absent opt-in flag")
				}
			} else if name == "false" {
				t.Setenv(key, "false")
			}
			c := Config{LiveOverviewEnabled: true, Mode: "lab.prod"}
			if err := overviewConfigFromEnvironment(&c); err != nil || c.LiveOverviewEnabled || c.Mode != "lab.prod" {
				t.Fatal("default or explicit off must disable only the overview flag")
			}
		})
	}
}

func TestLiveOverviewEnvironmentEnablesOnlyCanonicalTrue(t *testing.T) {
	t.Setenv("CHENGWANG_LIVE_OVERVIEW_ENABLED", "true")
	c := Config{Mode: "Shadow", ProbeReadEnabled: false, SubscriptionsEnabled: false}
	if err := overviewConfigFromEnvironment(&c); err != nil || !c.LiveOverviewEnabled {
		t.Fatal("canonical opt-in flag did not enable overview")
	}
	if c.Mode != "Shadow" || c.ProbeReadEnabled || c.SubscriptionsEnabled {
		t.Fatal("overview parsing changed another component configuration")
	}
}

func TestLiveOverviewEnvironmentRejectsNoncanonicalWithoutMutation(t *testing.T) {
	for _, raw := range []string{"TRUE", "FALSE", "True", "False", " true", "true ", "\ttrue", "false\n", "1", "0", "yes", "on"} {
		t.Setenv("CHENGWANG_LIVE_OVERVIEW_ENABLED", raw)
		c := Config{LiveOverviewEnabled: true, Mode: "lab.prod", MihomoURL: "not-read", MihomoAllowedHosts: []string{"not-read"}, ProbeReadEnabled: true, SubscriptionsEnabled: true}
		before := c
		before.MihomoAllowedHosts = append([]string(nil), c.MihomoAllowedHosts...)
		if err := overviewConfigFromEnvironment(&c); !errors.Is(err, errOverviewConfiguration) {
			t.Fatal("noncanonical flag was accepted or returned a different error")
		}
		if !reflect.DeepEqual(c, before) {
			t.Fatal("rejected environment partially changed configuration")
		}
	}
}

func TestLiveOverviewEnvironmentErrorsAreFixedAndNonEchoing(t *testing.T) {
	for _, raw := range []string{"sentinel-private-flag", "https://sentinel.invalid/private?token=sentinel", strings.Repeat("sentinel", 1024)} {
		t.Setenv("CHENGWANG_LIVE_OVERVIEW_ENABLED", raw)
		c := Config{}
		err := overviewConfigFromEnvironment(&c)
		if !errors.Is(err, errOverviewConfiguration) || err.Error() != "live overview configuration is invalid" || strings.Contains(err.Error(), "sentinel") {
			t.Fatal("configuration rejection did not use the fixed safe error")
		}
	}
}

func TestLiveOverviewEnvironmentRejectsNilConfig(t *testing.T) {
	for _, raw := range []string{"", "false", "true", "sentinel-invalid"} {
		t.Setenv("CHENGWANG_LIVE_OVERVIEW_ENABLED", raw)
		if err := overviewConfigFromEnvironment(nil); !errors.Is(err, errOverviewConfiguration) {
			t.Fatal("nil configuration must fail safely for any environment")
		}
	}
}
