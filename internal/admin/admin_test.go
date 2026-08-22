package admin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"tgwebproxy/internal/metrics"
)

func TestRefusesToListenBeyondLoopback(t *testing.T) {
	registry := metrics.New()
	for _, listen := range []string{":9600", "0.0.0.0:9600", "192.0.2.10:9600", "[::]:9600"} {
		if _, err := New(listen, registry, nil); err == nil {
			t.Errorf("%s was accepted; the admin listener exposes counters that "+
				"identify the relay and must stay on the loopback", listen)
		}
	}
	for _, listen := range []string{"127.0.0.1:9600", "localhost:9600", "[::1]:9600"} {
		if _, err := New(listen, registry, nil); err != nil {
			t.Errorf("%s was refused: %v", listen, err)
		}
	}
}

func serve(t *testing.T, ready ReadyFunc) string {
	t.Helper()
	registry := metrics.New()
	registry.Add("tgwp_sessions_started_total", 3, "domain", "a.example.com", "label", "phone")

	server, err := New("127.0.0.1:0", registry, ready)
	if err != nil {
		t.Fatal(err)
	}
	// Bind explicitly so the test knows the port.
	listener, err := listen(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go server.http.Serve(listener)
	return "http://" + listener.Addr().String()
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestEndpoints(t *testing.T) {
	base := serve(t, func(context.Context) error { return nil })

	if code, body := get(t, base+"/healthz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("healthz = %d %q", code, body)
	}
	if code, body := get(t, base+"/readyz"); code != 200 || !strings.Contains(body, "ok") {
		t.Errorf("readyz = %d %q", code, body)
	}
	code, body := get(t, base+"/metrics")
	if code != 200 {
		t.Fatalf("metrics = %d", code)
	}
	if !strings.Contains(body, `tgwp_sessions_started_total{domain="a.example.com",label="phone"} 3`) {
		t.Errorf("metrics body missing the series:\n%s", body)
	}
}

// Readiness answers the question a process cannot answer from inside itself:
// can this host reach Telegram. An unreachable data centre is not "healthy".
func TestReadyzReportsAnUnreachableDataCentre(t *testing.T) {
	base := serve(t, func(context.Context) error { return errors.New("no route to host") })
	if code, body := get(t, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d %q, want 503", code, body)
	}
	if code, _ := get(t, base+"/healthz"); code != 200 {
		t.Error("healthz must stay 200: the process itself is fine")
	}
}
