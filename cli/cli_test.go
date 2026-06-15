package cli

import (
	"context"
	"testing"
	"time"
)

func TestSetup(t *testing.T) {
	// No <PREFIX>_NATS_URL / _DEBUG_ADDR in the env ⇒ stdout-only logger,
	// no NATS dial, no diagnostics listener — keeps the test hermetic.
	parent, cancelParent := context.WithCancel(context.Background())
	rt := App{Name: "testd", EnvPrefix: "TESTD_CLI"}.Setup(parent)
	defer rt.Shutdown()

	if rt.Log == nil {
		t.Fatal("Setup returned nil Log")
	}
	if rt.Ctx == nil {
		t.Fatal("Setup returned nil Ctx")
	}
	if rt.Shutdown == nil {
		t.Fatal("Setup returned nil Shutdown")
	}

	select {
	case <-rt.Ctx.Done():
		t.Fatal("Ctx cancelled before parent cancel")
	default:
	}

	// Parent cancellation must propagate to the derived context.
	cancelParent()
	select {
	case <-rt.Ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Ctx did not cancel after parent cancel")
	}
}

func TestShutdownIsSafe(t *testing.T) {
	rt := App{Name: "testd", EnvPrefix: "TESTD_CLI"}.Setup(context.Background())
	rt.Shutdown() // must not panic and must release the signal hook
}

func TestNATSResolutionWorkloadFallback(t *testing.T) {
	a := App{Name: "x", EnvPrefix: "XCLI"}

	t.Setenv("XCLI_NATS_URL", "nats://broker:4222")
	t.Setenv("XCLI_WORKLOAD_CERT", "/w/cert.pem")
	t.Setenv("XCLI_WORKLOAD_KEY", "/w/key.pem")
	t.Setenv("XCLI_WORKLOAD_CA", "/w/ca.pem")

	// With no NATS-specific keys, cert/key/CA fall back to WORKLOAD_*.
	n := a.NATS()
	if n.URL != "nats://broker:4222" {
		t.Errorf("URL = %q", n.URL)
	}
	if n.CertFile != "/w/cert.pem" || n.KeyFile != "/w/key.pem" || n.CAFile != "/w/ca.pem" {
		t.Errorf("workload fallback not applied: %+v", n)
	}

	// A NATS-specific override wins over the workload identity.
	t.Setenv("XCLI_NATS_CERT", "/n/cert.pem")
	t.Setenv("XCLI_NATS_CA", "/n/ca.pem")
	n = a.NATS()
	if n.CertFile != "/n/cert.pem" || n.CAFile != "/n/ca.pem" {
		t.Errorf("NATS override not honored: %+v", n)
	}
	if n.KeyFile != "/w/key.pem" {
		t.Errorf("unset NATS key should still fall back to workload: %+v", n)
	}
}

func TestDBSplitFallback(t *testing.T) {
	a := App{Name: "x", EnvPrefix: "XCLI"}

	t.Setenv("XCLI_DATABASE_URL", "postgres://db/app")
	t.Setenv("XCLI_WORKLOAD_CERT", "/w/cert.pem")
	t.Setenv("XCLI_WORKLOAD_KEY", "/w/key.pem")
	t.Setenv("XCLI_WORKLOAD_CA", "/w/ca.pem")

	// cert/key are a DB-role credential — they do NOT borrow WORKLOAD_*.
	// CA is the shared trust root — it DOES fall back to WORKLOAD_CA.
	d := a.DB()
	if d.URL != "postgres://db/app" {
		t.Errorf("URL = %q", d.URL)
	}
	if d.CertFile != "" || d.KeyFile != "" {
		t.Errorf("DB cert/key must not fall back to workload: %+v", d)
	}
	if d.CAFile != "/w/ca.pem" {
		t.Errorf("DB CA should fall back to WORKLOAD_CA: %+v", d)
	}

	// DB-specific vars are honored verbatim and override the workload CA.
	t.Setenv("XCLI_DB_CERT", "/d/cert.pem")
	t.Setenv("XCLI_DB_KEY", "/d/key.pem")
	t.Setenv("XCLI_DB_CA", "/d/ca.pem")
	d = a.DB()
	if d.CertFile != "/d/cert.pem" || d.KeyFile != "/d/key.pem" || d.CAFile != "/d/ca.pem" {
		t.Errorf("DB vars not honored: %+v", d)
	}
}

func TestAdminDBFallbackChain(t *testing.T) {
	a := App{Name: "x", EnvPrefix: "XCLI"}

	// Only runtime DB vars set: AdminDB mirrors DB.
	t.Setenv("XCLI_DATABASE_URL", "postgres://db/app")
	t.Setenv("XCLI_DB_CERT", "/d/cert.pem")
	t.Setenv("XCLI_DB_KEY", "/d/key.pem")
	t.Setenv("XCLI_DB_CA", "/d/ca.pem")
	t.Setenv("XCLI_WORKLOAD_CERT", "/w/cert.pem") // must be ignored (cert is a DB credential)

	ad := a.AdminDB()
	if ad.URL != "postgres://db/app" || ad.CertFile != "/d/cert.pem" || ad.CAFile != "/d/ca.pem" {
		t.Errorf("AdminDB should mirror DB when ADMIN_* unset: %+v", ad)
	}

	// ADMIN_* cert/key overrides win; they do not fall back to workload.
	t.Setenv("XCLI_ADMIN_DATABASE_URL", "postgres://db/admin")
	t.Setenv("XCLI_ADMIN_DB_CERT", "/a/cert.pem")
	t.Setenv("XCLI_ADMIN_DB_KEY", "/a/key.pem")
	ad = a.AdminDB()
	if ad.URL != "postgres://db/admin" || ad.CertFile != "/a/cert.pem" || ad.KeyFile != "/a/key.pem" {
		t.Errorf("ADMIN_* not honored: %+v", ad)
	}
	if ad.CAFile != "/d/ca.pem" {
		t.Errorf("unset ADMIN_DB_CA should fall back to DB_CA: %+v", ad)
	}

	// CA continues the shared-root chain to WORKLOAD_CA when neither
	// ADMIN_DB_CA nor DB_CA is set (fresh prefix to keep DB_CA unset).
	b := App{Name: "y", EnvPrefix: "YCLI"}
	t.Setenv("YCLI_WORKLOAD_CA", "/w/ca.pem")
	if ad := b.AdminDB(); ad.CAFile != "/w/ca.pem" {
		t.Errorf("AdminDB CA should fall back to WORKLOAD_CA: %+v", ad)
	}
}

func TestAuditHelpersNoopWithoutURL(t *testing.T) {
	// No <PREFIX>_NATS_URL ⇒ no-op sink/source, no dial, no error.
	rt := App{Name: "x", EnvPrefix: "XAUD"}.Setup(context.Background())
	defer rt.Shutdown()

	sink, err := AuditSink[map[string]any](rt, "x.audit.events")
	if err != nil {
		t.Fatalf("AuditSink: %v", err)
	}
	if sink == nil {
		t.Fatal("AuditSink returned nil sink")
	}

	src, err := AuditSource(rt, "x_audit", "x.audit.events")
	if err != nil {
		t.Fatalf("AuditSource: %v", err)
	}
	if src == nil {
		t.Fatal("AuditSource returned nil source")
	}
}
