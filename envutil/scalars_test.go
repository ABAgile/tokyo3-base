package envutil_test

import (
	"net"
	"testing"
	"time"

	"github.com/abagile/tokyo3-base/envutil"
)

func TestFloat(t *testing.T) {
	t.Setenv("RL_RPS", "12.5")
	if f, err := envutil.Float("RL_RPS"); err != nil || f != 12.5 {
		t.Fatalf("Float = %v, %v; want 12.5, nil", f, err)
	}
	if f, err := envutil.Float("RL_UNSET"); err != nil || f != 0 {
		t.Fatalf("unset Float = %v, %v; want 0, nil", f, err)
	}
	t.Setenv("RL_BAD", "nope")
	if _, err := envutil.Float("RL_BAD"); err == nil {
		t.Error("malformed Float should error")
	}
}

func TestInt(t *testing.T) {
	t.Setenv("RL_BURST", "5")
	if n, err := envutil.Int("RL_BURST"); err != nil || n != 5 {
		t.Fatalf("Int = %v, %v; want 5, nil", n, err)
	}
	if n, err := envutil.Int("RL_UNSET"); err != nil || n != 0 {
		t.Fatalf("unset Int = %v, %v; want 0, nil", n, err)
	}
	t.Setenv("RL_BAD", "1.5")
	if _, err := envutil.Int("RL_BAD"); err == nil {
		t.Error("malformed Int should error")
	}
}

func TestDuration(t *testing.T) {
	t.Setenv("D", "750ms")
	if d, err := envutil.Duration("D"); err != nil || d != 750*time.Millisecond {
		t.Fatalf("Duration = %v, %v; want 750ms, nil", d, err)
	}
	if d, err := envutil.Duration("D_UNSET"); err != nil || d != 0 {
		t.Fatalf("unset Duration = %v, %v; want 0, nil", d, err)
	}
	t.Setenv("D_BAD", "5")
	if _, err := envutil.Duration("D_BAD"); err == nil {
		t.Error("bare-number Duration should error (no unit)")
	}
}

func TestCIDRList(t *testing.T) {
	t.Setenv("TP", "10.0.0.0/8, 192.168.1.1, ::1")
	nets, err := envutil.CIDRList("TP")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("len = %d, want 3", len(nets))
	}
	// Bare IPv4 → /32, bare IPv6 → /128.
	if ones, _ := nets[1].Mask.Size(); ones != 32 {
		t.Errorf("bare IPv4 mask = /%d, want /32", ones)
	}
	if ones, _ := nets[2].Mask.Size(); ones != 128 {
		t.Errorf("bare IPv6 mask = /%d, want /128", ones)
	}
	if nets, err := envutil.CIDRList("TP_UNSET"); err != nil || nets != nil {
		t.Fatalf("unset CIDRList = %v, %v; want nil, nil", nets, err)
	}
	t.Setenv("TP_BAD", "not-a-cidr")
	if _, err := envutil.CIDRList("TP_BAD"); err == nil {
		t.Error("malformed CIDRList should error")
	}
}

func TestFloat_RejectsNonFinite(t *testing.T) {
	for _, v := range []string{"NaN", "Inf", "-Inf", "+Inf"} {
		t.Setenv("RL_NONFINITE", v)
		if _, err := envutil.Float("RL_NONFINITE"); err == nil {
			t.Errorf("Float(%q) should error", v)
		}
	}
}

func TestCIDRList_IPv4MappedIPv6(t *testing.T) {
	t.Setenv("TP", "::ffff:10.0.0.1, ::ffff:192.168.0.0/112")
	nets, err := envutil.CIDRList("TP")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 || nets[0].String() != "10.0.0.1/32" || nets[1].String() != "192.168.0.0/16" {
		t.Fatalf("nets = %v, want [10.0.0.1/32 192.168.0.0/16]", nets)
	}
	if !nets[0].Contains(net.ParseIP("10.0.0.1")) || nets[0].Contains(net.ParseIP("10.0.0.2")) {
		t.Error("mapped host entry must match exactly the IPv4 host")
	}
}
