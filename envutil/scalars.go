package envutil

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Float reads the env var named by key as a float64. An unset or empty var
// yields (0, nil) so callers can apply their own default; a malformed value is
// an error naming the key.
func Float(key string) (float64, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

// Int reads the env var named by key as an int. Unset/empty ⇒ (0, nil);
// malformed ⇒ an error naming the key.
func Int(key string) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// Duration reads the env var named by key as a [time.Duration] (e.g. "750ms",
// "6h"). Unset/empty ⇒ (0, nil); malformed ⇒ an error naming the key. Callers
// wanting a default substitute it on the zero return; callers wanting to
// disable a feature on a bad value can log the error and treat it as "off".
func Duration(key string) (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// CIDRList reads the env var named by key as a comma-separated list of CIDRs;
// a bare IP is treated as a /32 (IPv4) or /128 (IPv6). Unset/empty ⇒ (nil,
// nil). A malformed entry is an error naming the key. Useful for trusted-proxy
// allow-lists.
func CIDRList(key string) ([]*net.IPNet, error) {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				if ip.To4() != nil {
					part += "/32"
				} else {
					part += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out = append(out, n)
	}
	return out, nil
}
