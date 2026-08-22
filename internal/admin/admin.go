// Package admin serves health and metrics on a private listener.
//
// It is deliberately a second listener rather than a path on 443. A relay
// whose public port answers /metrics is a relay anyone can fingerprint by
// asking, which would undo the capability gate it is built around.
package admin

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"tgwebproxy/internal/metrics"
)

// ReadyFunc reports whether the relay can currently reach Telegram.
type ReadyFunc func(ctx context.Context) error

type Server struct {
	http *http.Server
}

// New builds the admin server. A listen address that is not on the loopback
// is refused: exposing it is never what the operator meant.
func New(listen string, registry *metrics.Registry, ready ReadyFunc) (*Server, error) {
	if err := checkLoopback(listen); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready == nil {
			w.Write([]byte("ok\n"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := ready(ctx); err != nil {
			http.Error(w, "unreachable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		registry.WriteTo(w)
	})

	return &Server{http: &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}}, nil
}

func checkLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("admin: the admin listener must be on the loopback, " +
			"since it exposes counters that identify the relay")
	}
	return nil
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errs:
		s.shutdown()
		return err
	}
	s.shutdown()
	return nil
}

func (s *Server) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

func (s *Server) Addr() string { return s.http.Addr }

// listen binds the configured address, so a caller (a test, mainly) can learn
// the port before serving.
func listen(s *Server) (net.Listener, error) {
	return net.Listen("tcp", s.http.Addr)
}
