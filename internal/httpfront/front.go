// Package httpfront is the public face of the relay. A visitor without the
// capability must not be able to tell this domain from an ordinary site: every
// request goes through the same constant-time check, and a failed check yields
// the cover site with the same status, headers and bytes. Bridge and WebSocket
// both live on "/", so there is no second path to discover.
package httpfront

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"tgwebproxy/internal/relay"
	"tgwebproxy/internal/secret"
	"tgwebproxy/internal/webassets"
)

type Config struct {
	// Domain is the normalised host the capability is bound to.
	Domain string
	// Keyring holds every secret this relay accepts.
	Keyring *secret.Keyring
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
	domain      string
	log         *slog.Logger
	relay       relay.Options
	behindProxy bool
	diagnose    bool
	upgrader    websocket.Upgrader
	sessions    *sessionRegistry
	// live is swapped whole on reload, so a request either sees the old
	// snapshot or the new one and never a mixture.
	live atomic.Pointer[liveState]
}

// Live is the part of the configuration that may change while the relay runs.
type Live struct {
	Keyring    *secret.Keyring
	SiteDir    string
	MaxStreams int
}

type liveState struct {
	keyring    *secret.Keyring
	cover      http.Handler
	maxStreams int
}

// New fails on an unusable site directory: a broken cover site would be worse
// than no relay at all.
func New(cfg Config) (*Handler, error) {
	if cfg.Domain == "" {
		return nil, errors.New("httpfront: domain is required")
	}
	if cfg.Keyring == nil || cfg.Keyring.Len() == 0 {
		return nil, errors.New("httpfront: at least one secret is required")
	}
	if cfg.Keyring.Host() != cfg.Domain {
		return nil, errors.New("httpfront: the keyring was built for a different host")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cover, err := coverHandler(cfg.SiteDir)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		domain:      cfg.Domain,
		log:         cfg.Logger,
		relay:       cfg.Relay,
		behindProxy: cfg.BehindProxy,
		diagnose:    cfg.Diagnose,
		sessions:    newSessionRegistry(),
	}
	h.live.Store(&liveState{
		keyring:    cfg.Keyring,
		cover:      cover,
		maxStreams: cfg.Relay.MaxStreams,
	})
	h.upgrader = websocket.Upgrader{
		HandshakeTimeout: 15 * time.Second,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		CheckOrigin:      h.checkOrigin,
	}
	return h, nil
}

// Reload installs a new snapshot. Everything is validated before the running
// state is touched, so a bad configuration leaves the relay as it was.
func (h *Handler) Reload(next Live) error {
	if next.Keyring == nil || next.Keyring.Len() == 0 {
		return errors.New("httpfront: reload needs at least one secret")
	}
	if next.Keyring.Host() != h.domain {
		return errors.New("httpfront: reload cannot change the domain")
	}
	cover, err := coverHandler(next.SiteDir)
	if err != nil {
		return err
	}
	maxStreams := next.MaxStreams
	if maxStreams <= 0 {
		maxStreams = h.live.Load().maxStreams
	}
	h.live.Store(&liveState{
		keyring:    next.Keyring,
		cover:      cover,
		maxStreams: maxStreams,
	})
	if dropped := h.sessions.revokeMissing(next.Keyring); len(dropped) > 0 {
		h.log.Info("secrets revoked, sessions closed", "labels", dropped)
	}
	h.log.Info("configuration reloaded", "secrets", next.Keyring.Len())
	return nil
}

func (h *Handler) Domain() string { return h.domain }

func coverHandler(siteDir string) (http.Handler, error) {
	if siteDir == "" {
		return http.HandlerFunc(builtinCover), nil
	}
	info, err := os.Stat(siteDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("httpfront: site path is not a directory")
	}
	if _, err := os.Stat(filepath.Join(siteDir, "index.html")); err != nil {
		return nil, errors.New("httpfront: site directory has no index.html")
	}
	return http.FileServer(http.Dir(siteDir)), nil
}

func builtinCover(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(webassets.CoverPage())
}

// checkOrigin accepts every origin, deliberately. Telegram's own reference
// relay dropped its origin check for the same reason (tproxy-server commit
// "Remove origin checks"): a native WebView may omit the header entirely, so
// requiring it locks out the very client this exists for. Nothing is lost —
// a non-browser peer can forge any origin, and the capability in the query is
// what actually authenticates the upgrade.
func (h *Handler) checkOrigin(*http.Request) bool {
	return true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := h.live.Load()
	entry, authorized := h.match(state, r)
	upgrade := websocket.IsWebSocketUpgrade(r)

	if h.diagnose {
		label := ""
		if authorized {
			label = entry.Label
		}
		h.log.Info("request",
			"peer", h.peerLabel(r),
			"authorized", authorized,
			"label", label,
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
			state.cover.ServeHTTP(w, r)
			return
		}
		h.serveRelay(w, r, state, entry)
		return
	}
	if authorized {
		h.serveBridge(w, r, state)
		return
	}
	state.cover.ServeHTTP(w, r)
}

// match runs the capability check for every request, authorised or not, so
// the work done before the response is identical either way.
func (h *Handler) match(state *liveState, r *http.Request) (secret.Entry, bool) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		return secret.Entry{}, false
	}
	return state.keyring.Match(r.URL.Query().Get("bridge"))
}

func (h *Handler) serveBridge(w http.ResponseWriter, r *http.Request, state *liveState) {
	page, nonce, err := webassets.Bridge()
	if err != nil {
		h.log.Error("cannot render the bridge page", "error", err)
		state.cover.ServeHTTP(w, r)
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
		"connect-src wss://" + h.domain,
		"base-uri 'none'",
		"form-action 'none'",
	}, "; "))
	w.Write(page)
}

func (h *Handler) serveRelay(w http.ResponseWriter, r *http.Request, state *liveState, entry secret.Entry) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Debug("upgrade failed", "error", err)
		return
	}
	// One Data frame plus its header is the largest legitimate message.
	conn.SetReadLimit(2 * 1024 * 1024)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Closing the socket is not optional: the session's reader blocks in
	// ReadMessage, and cancelling the context alone would never wake it.
	id := h.sessions.add(entry, func() {
		cancel()
		_ = conn.Close()
	})
	defer h.sessions.remove(id)

	opts := h.relay
	opts.Secret = entry.Secret
	opts.MaxStreams = state.maxStreams
	opts.Logger = h.log.With("peer", h.peerLabel(r), "label", entry.Label)

	if err := relay.Serve(ctx, &wsConn{conn: conn}, opts); err != nil {
		if errors.Is(err, relay.ErrProtocol) {
			h.log.Warn("session dropped", "reason", err, "label", entry.Label)
		} else {
			h.log.Debug("session ended", "reason", err, "label", entry.Label)
		}
	}
}

// peerLabel identifies a session in logs without recording a full address.
// Behind a front end the socket address is always the front end, so the first
// X-Forwarded-For hop is used instead.
func (h *Handler) peerLabel(r *http.Request) string {
	if h.behindProxy {
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
