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
		domain      = flag.String("domain", env("TGWP_DOMAIN", ""), "domain this relay answers on (required)")
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

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(strings.ToLower(*logLevel))); err != nil {
		return fmt.Errorf("bad log level %q", *logLevel)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *domain == "" {
		return fmt.Errorf("-domain is required")
	}
	// The client hashes its normalised spelling of the domain, so the relay
	// must hash the same spelling or the capability never matches.
	normalized, err := hostname.Normalize(*domain)
	if err != nil {
		return fmt.Errorf("domain %q: %w", *domain, err)
	}
	if normalized != *domain {
		log.Info("domain normalised", "from", *domain, "to", normalized)
	}

	var sec secret.Secret
	if *secretText == "" {
		sec, err = secret.Generate()
		if err != nil {
			return err
		}
		log.Warn("no secret supplied, generated a new one; pass it with -secret to keep it across restarts")
	} else {
		sec, err = secret.Parse(*secretText)
		if err != nil {
			return err
		}
	}

	handler, err := httpfront.New(httpfront.Config{
		Domain:      normalized,
		Secret:      sec,
		SiteDir:     *siteDir,
		Logger:      log,
		BehindProxy: *behindProxy,
		Diagnose:    *diagnose,
		Relay: relay.Options{
			MaxStreams:   *maxStreams,
			PingInterval: 30 * time.Second,
			IdleTimeout:  90 * time.Second,
			DialTimeout:  10 * time.Second,
		},
	})
	if err != nil {
		return err
	}

	printConnectionDetails(normalized, sec)

	serverCfg := httpfront.ServerConfig{
		Listen:      *listen,
		CertDir:     *certDir,
		PlainListen: *plainListen,
	}
	if *behindProxy {
		serverCfg.Plaintext = true
		serverCfg.PlainListen = ""
		if *listen == ":443" {
			// Plaintext on every interface would expose the relay without TLS.
			serverCfg.Listen = "127.0.0.1:4600"
		}
	}
	server := httpfront.NewServer(handler, serverCfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("relay listening",
		"address", serverCfg.Listen,
		"domain", normalized,
		"behind_proxy", *behindProxy)
	return server.Run(ctx)
}

func printConnectionDetails(domain string, sec secret.Secret) {
	fmt.Println()
	fmt.Println("  Telegram Desktop -> Settings -> Advanced -> Connection type -> Add proxy -> WEB")
	fmt.Println()
	fmt.Printf("    Web proxy hostname : %s\n", domain)
	fmt.Printf("    Secret             : %s\n", sec.Hex())
	fmt.Println()
	fmt.Printf("    (base64url form    : %s)\n", sec.Base64URL())
	fmt.Printf("    (bridge capability : %s)\n", sec.Capability(domain))
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
