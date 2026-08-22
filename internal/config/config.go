// Package config parses the relay's TOML configuration into a validated,
// immutable snapshot. It performs no I/O beyond reading the file and knows
// nothing about signals: reloading is the caller's business.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"tgwebproxy/internal/hostname"
	"tgwebproxy/internal/secret"
)

type file struct {
	Domain      string      `toml:"domain"`
	Listen      string      `toml:"listen"`
	PlainListen string      `toml:"plain_listen"`
	BehindProxy bool        `toml:"behind_proxy"`
	CertDir     string      `toml:"cert_dir"`
	LogLevel    string      `toml:"log_level"`
	MaxStreams  int         `toml:"max_streams"`
	Site        string      `toml:"site"`
	Diagnose    bool        `toml:"diagnose"`
	Secrets     []fileEntry `toml:"secret"`
}

type fileEntry struct {
	Value string `toml:"value"`
	Label string `toml:"label"`
}

// Config is a validated snapshot. Everything in it is already normalised, so
// consumers never repeat validation.
type Config struct {
	Domain      string
	Listen      string
	PlainListen string
	CertDir     string
	Site        string
	BehindProxy bool
	Diagnose    bool
	LogLevel    slog.Level
	MaxStreams  int
	Entries     []secret.Entry
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func Parse(data []byte) (*Config, error) {
	var raw file
	meta, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, err
	}
	// A typo in a key would otherwise be ignored, leaving the operator to
	// wonder why the setting had no effect.
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		names := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			names = append(names, key.String())
		}
		return nil, fmt.Errorf("config: unknown key(s): %s", strings.Join(names, ", "))
	}

	cfg := &Config{
		Listen:      ":443",
		PlainListen: ":80",
		CertDir:     "certs",
		LogLevel:    slog.LevelInfo,
		MaxStreams:  64,
		BehindProxy: raw.BehindProxy,
		Diagnose:    raw.Diagnose,
		Site:        raw.Site,
	}

	if raw.Domain == "" {
		return nil, errors.New("config: domain is required")
	}
	// The client hashes its normalised spelling of the host into the
	// capability, so the relay must store the same spelling.
	normalized, err := hostname.Normalize(raw.Domain)
	if err != nil {
		return nil, fmt.Errorf("config: domain %q: %w", raw.Domain, err)
	}
	cfg.Domain = normalized

	if raw.Listen != "" {
		cfg.Listen = raw.Listen
	}
	if raw.PlainListen != "" {
		cfg.PlainListen = raw.PlainListen
	}
	if raw.CertDir != "" {
		cfg.CertDir = raw.CertDir
	}
	if raw.MaxStreams != 0 {
		if raw.MaxStreams < 1 {
			return nil, fmt.Errorf("config: max_streams must be positive, got %d", raw.MaxStreams)
		}
		cfg.MaxStreams = raw.MaxStreams
	}
	if raw.LogLevel != "" {
		var level slog.Level
		if err := level.UnmarshalText([]byte(strings.ToLower(raw.LogLevel))); err != nil {
			return nil, fmt.Errorf("config: log_level %q is not one of debug, info, warn, error", raw.LogLevel)
		}
		cfg.LogLevel = level
	}

	if len(raw.Secrets) == 0 {
		return nil, errors.New("config: at least one [[secret]] is required")
	}
	labels := make(map[string]struct{}, len(raw.Secrets))
	for i, entry := range raw.Secrets {
		parsed, err := secret.Parse(entry.Value)
		if err != nil {
			return nil, fmt.Errorf("config: secret %d: %w", i+1, err)
		}
		label := strings.TrimSpace(entry.Label)
		if label == "" {
			label = fmt.Sprintf("secret-%d", i+1)
		}
		if _, clash := labels[label]; clash {
			return nil, fmt.Errorf("config: label %q is used twice", label)
		}
		labels[label] = struct{}{}
		cfg.Entries = append(cfg.Entries, secret.Entry{Secret: parsed, Label: label})
	}
	return cfg, nil
}

// CheckStaticMatch reports the first setting that cannot change while the
// relay runs. The domain is baked into every capability, into the ACME host
// policy and into the CSP of pages already served; the listeners are bound.
func (c *Config) CheckStaticMatch(next *Config) error {
	for _, field := range []struct {
		name       string
		old, fresh string
	}{
		{"domain", c.Domain, next.Domain},
		{"listen", c.Listen, next.Listen},
		{"plain_listen", c.PlainListen, next.PlainListen},
		{"cert_dir", c.CertDir, next.CertDir},
	} {
		if field.old != field.fresh {
			return fmt.Errorf("config: %s cannot change without a restart (%q -> %q)",
				field.name, field.old, field.fresh)
		}
	}
	if c.BehindProxy != next.BehindProxy {
		return fmt.Errorf("config: behind_proxy cannot change without a restart (%v -> %v)",
			c.BehindProxy, next.BehindProxy)
	}
	return nil
}
