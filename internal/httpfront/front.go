// Package httpfront is the public face of the relay. A visitor without the
// capability must not be able to tell this domain from an ordinary site: every
// request goes through the same constant-time check, and a failed check yields
// the cover site with the same status, headers and bytes. Bridge and WebSocket
// both live on "/", so there is no second path to discover.
package httpfront

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/webassets"
)

type Config struct {
	// Domain is the normalised host the capability is bound to.
	Domain string
	Secret secret.Secret
	// SiteDir optionally replaces the built-in cover site with static files.
	SiteDir string
	Logger  *slog.Logger
	Relay   relay.Options
	// BehindProxy marks that a trusted front end terminates TLS. Only then is
	// X-Forwarded-For trustworthy; exposed directly, any client could forge it.
	BehindProxy bool
	// Diagnose logs one line per request (never the capability itself). Off by
	// default: a relay that keeps request logs can betray its users.
	Diagnose bool
}

// Handler serves the cover site, the bridge page, and the relay socket.
type Handler struct {
	cfg      Config
	log      *slog.Logger
	cover    http.Handler
	upgrader websocket.Upgrader
}

// New fails on an unusable site directory: a broken cover site would be worse
// than no relay at all.
func New(cfg Config) (*Handler, error) {
	if cfg.Domain == "" {
		return nil, errors.New("httpfront: domain is required")
	}
	if !cfg.Secret.Valid() {
		return nil, errors.New("httpfront: secret is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	var cover http.Handler
	if cfg.SiteDir != "" {
		info, err := os.Stat(cfg.SiteDir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errors.New("httpfront: site path is not a directory")
		}
		if _, err := os.Stat(filepath.Join(cfg.SiteDir, "index.html")); err != nil {
			return nil, errors.New("httpfront: site directory has no index.html")
		}
		cover = http.FileServer(http.Dir(cfg.SiteDir))
	} else {
		cover = http.HandlerFunc(builtinCover)
	}

	h := &Handler{
		cfg:   cfg,
		log:   cfg.Logger,
		cover: cover,
	}
	h.upgrader = websocket.Upgrader{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		CheckOrigin:      h.checkOrigin,
	}
	return h, nil
}

func builtinCover(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(webassets.CoverPage())
}

// checkOrigin accepts only our own origin. In the hidden WebView the bridge
// page is the top document on this domain; in the browser fallback it runs in
// a same-origin iframe. Either way the Origin header is our own https origin.
func (h *Handler) checkOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == "https://"+h.cfg.Domain
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authorized := h.authorized(r)
	upgrade := websocket.IsWebSocketUpgrade(r)

	if h.cfg.Diagnose {
		h.log.Info("request",
			"peer", h.peerLabel(r),
			"authorized", authorized,
			"upgrade", upgrade,
			"method", r.Method,
			"path", r.URL.Path,
			"has_bridge_param", r.URL.Query().Has("bridge"),
			"agent", shortAgent(r.UserAgent()))
	}

	if upgrade {
		if !authorized {
			// Answer an unauthorised upgrade the way a site with no
			// WebSocket endpoint would: with the page itself.
			h.cover.ServeHTTP(w, r)
			return
		}
		h.serveRelay(w, r)
		return
	}
	if authorized {
		h.serveBridge(w, r)
		return
	}
	h.cover.ServeHTTP(w, r)
}

// authorized runs the capability check for every request, authorised or not,
// so the work done before the response is identical either way.
func (h *Handler) authorized(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if r.URL.Path != "/" {
		return false
	}
	return h.cfg.Secret.CheckCapability(h.cfg.Domain, r.URL.Query().Get("bridge"))
}

func (h *Handler) serveBridge(w http.ResponseWriter, r *http.Request) {
	page, nonce, err := webassets.Bridge()
	if err != nil {
		h.log.Error("cannot render the bridge page", "error", err)
		h.cover.ServeHTTP(w, r)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"style-src 'unsafe-inline'",
		"connect-src wss://" + h.cfg.Domain,
		"base-uri 'none'",
		"form-action 'none'",
	}, "; "))
	w.Write(page)
}

func (h *Handler) serveRelay(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Debug("upgrade failed", "error", err)
		return
	}
	// One Data frame plus its header is the largest legitimate message.
	conn.SetReadLimit(2 * 1024 * 1024)

	opts := h.cfg.Relay
	opts.Secret = h.cfg.Secret
	opts.Logger = h.log.With("peer", h.peerLabel(r))

	if err := relay.Serve(r.Context(), &wsConn{conn: conn}, opts); err != nil {
		if errors.Is(err, relay.ErrProtocol) {
			h.log.Warn("session dropped", "reason", err)
		} else {
			h.log.Debug("session ended", "reason", err)
		}
	}
}

// peerLabel identifies a session in logs without recording a full address.
// Behind a front end the socket address is always the front end, so the first
// X-Forwarded-For hop is used instead.
func (h *Handler) peerLabel(r *http.Request) string {
	if h.cfg.BehindProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			first := forwarded
			if idx := strings.Index(first, ","); idx >= 0 {
				first = first[:idx]
			}
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// The user agent tells "no WebView at all" from "a WebView that failed later".
func shortAgent(agent string) string {
	const limit = 96
	if len(agent) > limit {
		return agent[:limit]
	}
	return agent
}

// wsConn adapts a gorilla WebSocket to relay.MessageConn. The relay reads from
// one goroutine and writes from one other, as gorilla requires.
type wsConn struct {
	conn *websocket.Conn
}

func (c *wsConn) ReadMessage() ([]byte, error) {
	kind, data, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if kind != websocket.BinaryMessage {
		// A text message means the peer is not our bridge page.
		return nil, errors.New("httpfront: non-binary transport message")
	}
	return data, nil
}

func (c *wsConn) WriteMessage(data []byte) error {
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *wsConn) Close() error { return c.conn.Close() }

var _ relay.MessageConn = (*wsConn)(nil)
