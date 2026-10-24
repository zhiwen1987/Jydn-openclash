package serverruntime

// These are configuration/ownership MODEL tests. They do not start a service,
// prove live authentication, run a kernel, or certify production readiness.
import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"chengwang/internal/api"
	"chengwang/internal/mihomodeploy"
)

func modelMihomoLabConfig() Config {
	return Config{MihomoLabEnabled: true, Mode: mihomodeploy.LabEnvironment, IdentitiesFile: MihomoLabIdentityFile,
		TenantID: "lab-tenant", SiteID: "lab-site", ManagementObjectID: "lab-device"}
}

func TestMihomoLabDisabledCompositionDoesNotConstructIdentityOrKernel(t *testing.T) {
	r, err := OpenMihomoLabRuntime(nil, Config{IdentitiesFile: "MODEL_MUST_NOT_OPEN"})
	if err != nil || r != nil {
		t.Fatal("disabled composition must have no runtime side effects")
	}
}

func TestMihomoLabEnabledCompositionRejectsMissingOrCancelledContext(t *testing.T) {
	if r, err := OpenMihomoLabRuntime(nil, modelMihomoLabConfig()); r != nil || err == nil {
		t.Fatal("nil context accepted")
	}
	var typedNil *struct{ context.Context }
	if r, err := OpenMihomoLabRuntime(typedNil, modelMihomoLabConfig()); r != nil || err == nil {
		t.Fatal("typed-nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err := OpenMihomoLabRuntime(ctx, modelMihomoLabConfig()); r != nil || err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func TestMihomoLabExplicitEnvironmentGateHasNoTruthyAliases(t *testing.T) {
	for _, value := range []string{"", "false", "true", "TRUE", "1", " true", "false "} {
		t.Run(fmt.Sprintf("value-%q", value), func(t *testing.T) {
			t.Setenv("CHENGWANG_MIHOMO_LAB_ENABLED", value)
			var c Config
			err := mihomoLabConfigFromEnvironment(&c)
			valid := value == "" || value == "false" || value == "true"
			if (err == nil) != valid || c.MihomoLabEnabled != (value == "true") {
				t.Fatal("feature flag alias or wrong default")
			}
		})
	}
}

func TestMihomoLabConfigRequiresFixedCredentialFileAndFullLabScope(t *testing.T) {
	if validateMihomoLabConfig(modelMihomoLabConfig()) != nil {
		t.Fatal("source-owned model configuration rejected")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Mode = "shadow" },
		func(c *Config) { c.Mode = "candidate" },
		func(c *Config) { c.IdentitiesFile = "" },
		func(c *Config) { c.IdentitiesFile += ".other" },
		func(c *Config) { c.TenantID = "" },
		func(c *Config) { c.SiteID = "" },
		func(c *Config) { c.ManagementObjectID = "" },
		func(c *Config) { c.TenantID = "tenant/alias" },
		func(c *Config) { c.SiteID = strings.Repeat("a", 129) },
	} {
		c := modelMihomoLabConfig()
		mutate(&c)
		if validateMihomoLabConfig(c) == nil {
			t.Fatal("incomplete or aliased fixed scope accepted")
		}
	}
}

func TestMihomoLabConfigRejectsSharedCredentialsAndUnownedTargetComposition(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.AdminToken = "MODEL_SHARED_TOKEN" },
		func(c *Config) { c.MihomoURL = "http://127.0.0.1:9090" },
		func(c *Config) { c.MihomoToken = "MODEL_UNOWNED_TOKEN" },
		func(c *Config) { c.MihomoAllowedHosts = []string{"127.0.0.1"} },
		func(c *Config) { c.AllowPublish = true },
		func(c *Config) { c.OperationWritesEnabled = true },
		func(c *Config) { c.SubscriptionsEnabled = true },
		func(c *Config) { c.SubscriptionWritesEnabled = true },
		func(c *Config) { c.ProbeReadEnabled = true },
		func(c *Config) { c.LiveOverviewEnabled = true },
	} {
		c := modelMihomoLabConfig()
		mutate(&c)
		if validateMihomoLabConfig(c) == nil {
			t.Fatal("mixed unowned composition accepted")
		}
	}
}

func TestMihomoLabNilZeroClosingAndClosedRuntimeExposeNoBackend(t *testing.T) {
	for _, r := range []*MihomoLabRuntime{nil, {}, {core: &mihomoLabRuntimeCore{}},
		{core: &mihomoLabRuntimeCore{ready: true, closing: true}}, {core: &mihomoLabRuntimeCore{ready: true, closed: true}}} {
		if r.Backend() != nil {
			t.Fatal("invalid runtime exposed backend")
		}
		options := r.ApplyAPIOptions(api.Options{Mode: "MODEL_MODE", OperationWritesEnabled: true, MihomoLabWritesEnabled: true})
		if options.MihomoLab != nil || options.MihomoLabWritesEnabled || !options.OperationWritesEnabled || options.Mode != "MODEL_MODE" {
			t.Fatal("disabled lab composition altered unrelated gates or leaked a backend")
		}
	}
}

func TestMihomoLabRuntimePrivateFormattingAndJSONCannotImportAuthority(t *testing.T) {
	r := MihomoLabRuntime{core: &mihomoLabRuntimeCore{}}
	for _, value := range []any{r, &r} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%+d", "%#f"} {
			out := fmt.Sprintf(verb, value)
			if strings.Contains(out, "credentials.json") || strings.Contains(out, "manager:") || strings.Contains(out, "service:") {
				t.Fatal("private runtime implementation formatted")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"ISOLATED_LAB_RUNTIME_NOT_AUTHORIZATION"}` {
			t.Fatal("unsafe runtime JSON")
		}
	}
	var imported MihomoLabRuntime
	if json.Unmarshal([]byte(`{"ready":true,"writable":true}`), &imported) == nil || imported.Backend() != nil {
		t.Fatal("runtime authority imported from JSON")
	}
}

func TestMihomoLabRuntimeCloseWithInvalidContextRetainsOwnership(t *testing.T) {
	core := &mihomoLabRuntimeCore{ready: true, writable: true}
	r := &MihomoLabRuntime{core: core}
	if r.Close(nil) == nil || r.core != core || !core.ready || core.closed {
		t.Fatal("invalid close discarded ownership")
	}
	var typedNil *struct{ context.Context }
	if r.Close(typedNil) == nil || r.core != core || !core.ready || core.closed {
		t.Fatal("typed-nil close discarded ownership")
	}
	if r.Close(context.Background()) != nil || !core.closed || core.ready || core.writable {
		t.Fatal("resource-free model close did not settle")
	}
	if r.Close(context.Background()) != nil {
		t.Fatal("settled close not idempotent")
	}
}
