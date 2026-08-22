// Command tgwebproxy is a relay for the WEB proxy type in Telegram Desktop
// 7.1.1: an ordinary web site on 443 and, only to a client that knows the
// secret, a bridge page whose WebSocket carries multiplexed MTProto traffic.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tgwebproxy/internal/config"
	"tgwebproxy/internal/hostname"
	"tgwebproxy/internal/httpfront"
	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", env("TGWP_CONFIG", ""), "TOML configuration file; enables several secrets and SIGHUP reload")
		domain      = flag.String("domain", env("TGWP_DOMAIN", ""), "domain this relay answers on (required without -config)")
		secretText  = flag.String("secret", env("TGWP_SECRET", ""), "MTProxy secret, hex or base64url; generated when empty")
		siteDir     = flag.String("site", env("TGWP_SITE", ""), "directory with the cover site; a built-in page is used when empty")
		certDir     = flag.String("cert-dir", env("TGWP_CERT_DIR", "certs"), "directory for ACME certificates")
		listen      = flag.String("listen", env("TGWP_LISTEN", ":443"), "TLS listen address")
		plainListen = flag.String("plain-listen", env("TGWP_PLAIN_LISTEN", ":80"), "plain HTTP listen address; empty disables it")
		maxStreams  = flag.Int("max-streams", 64, "concurrent MTProto streams per session")
		diagnose    = flag.Bool("diagnose", envBool("TGWP_DIAGNOSE"), "log one line per request; never logs the capability itself")
		behindProxy = flag.Bool("behind-proxy", envBool("TGWP_BEHIND_PROXY"), "serve plain HTTP for a reverse proxy that terminates TLS")
		logLevel    = flag.String("log-level", env("TGWP_LOG_LEVEL", "info"), "debug, info, warn or error")
	)
	flag.Parse()

	cfg, err := resolveConfig(*configPath, flagValues{
		domain:      *domain,
		secretText:  *secretText,
		siteDir:     *siteDir,
		certDir:     *certDir,
		listen:      *listen,
		plainListen: *plainListen,
		maxStreams:  *maxStreams,
		diagnose:    *diagnose,
		behindProxy: *behindProxy,
		logLevel:    *logLevel,
	})
	if err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	keyring, err := secret.NewKeyring(cfg.Domain, cfg.Entries)
	if err != nil {
		return err
	}
	handler, err := httpfront.New(httpfront.Config{
		Domain:      cfg.Domain,
		Keyring:     keyring,
		SiteDir:     cfg.Site,
		Logger:      log,
		BehindProxy: cfg.BehindProxy,
		Diagnose:    cfg.Diagnose,
		Relay: relay.Options{
			MaxStreams:   cfg.MaxStreams,
			PingInterval: 30 * time.Second,
			IdleTimeout:  90 * time.Second,
			DialTimeout:  10 * time.Second,
		},
	})
	if err != nil {
		return err
	}

	printConnectionDetails(cfg)

	serverCfg := httpfront.ServerConfig{
		Listen:      cfg.Listen,
		CertDir:     cfg.CertDir,
		PlainListen: cfg.PlainListen,
	}
	if cfg.BehindProxy {
		serverCfg.Plaintext = true
		serverCfg.PlainListen = ""
	}
	server := httpfront.NewServer(handler, serverCfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *configPath != "" {
		go watchReloads(ctx, *configPath, cfg, handler, log)
	}

	log.Info("relay listening",
		"address", serverCfg.Listen,
		"domain", cfg.Domain,
		"secrets", len(cfg.Entries),
		"behind_proxy", cfg.BehindProxy)
	return server.Run(ctx)
}

type flagValues struct {
	domain      string
	secretText  string
	siteDir     string
	certDir     string
	listen      string
	plainListen string
	maxStreams  int
	diagnose    bool
	behindProxy bool
	logLevel    string
}

// resolveConfig produces one snapshot from either the file or the flags. The
// two are never merged: a half-configured relay is worse than a refusal.
func resolveConfig(path string, flags flagValues) (*config.Config, error) {
	if path != "" {
		if flags.domain != "" || flags.secretText != "" {
			return nil, fmt.Errorf("-config cannot be combined with -domain or -secret")
		}
		return config.Load(path)
	}

	if flags.domain == "" {
		return nil, fmt.Errorf("-domain is required (or pass -config)")
	}
	// The client hashes its normalised spelling of the domain, so the relay
	// must hash the same spelling or the capability never matches.
	normalized, err := hostname.Normalize(flags.domain)
	if err != nil {
		return nil, fmt.Errorf("domain %q: %w", flags.domain, err)
	}

	var sec secret.Secret
	if flags.secretText == "" {
		if sec, err = secret.Generate(); err != nil {
			return nil, err
		}
	} else if sec, err = secret.Parse(flags.secretText); err != nil {
		return nil, err
	}

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(strings.ToLower(flags.logLevel))); err != nil {
		return nil, fmt.Errorf("bad log level %q", flags.logLevel)
	}

	listen := flags.listen
	if flags.behindProxy && listen == ":443" {
		// Behind a front end, listening on every interface would expose the
		// relay without TLS. Keep it on the loopback by default.
		listen = "127.0.0.1:4600"
	}

	return &config.Config{
		Domain:      normalized,
		Listen:      listen,
		PlainListen: flags.plainListen,
		CertDir:     flags.certDir,
		Site:        flags.siteDir,
		BehindProxy: flags.behindProxy,
		Diagnose:    flags.diagnose,
		LogLevel:    level,
		MaxStreams:  flags.maxStreams,
		Entries:     []secret.Entry{{Secret: sec, Label: "default"}},
	}, nil
}

// watchReloads applies SIGHUP. A rejected reload keeps the running
// configuration: reloading must never be a way to take the relay down.
func watchReloads(ctx context.Context, path string, current *config.Config, handler *httpfront.Handler, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			next, err := config.Load(path)
			if err != nil {
				log.Error("reload refused: the file did not parse", "error", err)
				continue
			}
			if err := current.CheckStaticMatch(next); err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			keyring, err := secret.NewKeyring(next.Domain, next.Entries)
			if err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			if err := handler.Reload(httpfront.Live{
				Keyring:    keyring,
				SiteDir:    next.Site,
				MaxStreams: next.MaxStreams,
			}); err != nil {
				log.Error("reload refused", "error", err)
				continue
			}
			current = next
		}
	}
}

func printConnectionDetails(cfg *config.Config) {
	fmt.Println()
	fmt.Println("  Telegram Desktop -> Settings -> Advanced -> Connection type -> Add proxy -> WEB")
	fmt.Println()
	fmt.Printf("    Web proxy hostname : %s\n", cfg.Domain)
	for _, entry := range cfg.Entries {
		fmt.Printf("    Secret (%s) : %s\n", entry.Label, entry.Secret.Hex())
	}
	fmt.Println()
}

func envBool(name string) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}
