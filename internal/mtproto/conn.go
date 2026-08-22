package mtproto

import (
	"context"
	"crypto/cipher"
	"fmt"
	"io"
	"net"
	"time"

	"tgwebproxy/internal/dc"
)

// Stream wraps a byte stream in an obfuscated2 keystream pair. Both directions
// are AES-256-CTR, a pure XOR: no framing, no buffering between calls.
type Stream struct {
	raw     io.ReadWriteCloser
	decrypt cipher.Stream
	encrypt cipher.Stream
	scratch []byte
}

func NewStream(raw io.ReadWriteCloser, decrypt, encrypt cipher.Stream) *Stream {
	return &Stream{raw: raw, decrypt: decrypt, encrypt: encrypt}
}

func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.raw.Read(p)
	if n > 0 {
		s.decrypt.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// Write encrypts through a scratch buffer, leaving the caller's slice intact.
func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if cap(s.scratch) < len(p) {
		s.scratch = make([]byte, len(p))
	}
	buf := s.scratch[:len(p)]
	s.encrypt.XORKeyStream(buf, p)
	return s.raw.Write(buf)
}

func (s *Stream) Close() error { return s.raw.Close() }

// DialDC talks to the DC as a proxy-less client would: the client's own
// transport tag so framing passes through untouched, no secret so the keys are
// the raw handshake material, and the DC id forwarded verbatim.
func DialDC(
	ctx context.Context,
	target dc.Target,
	protocol uint32,
	dcID int16,
	dialer *net.Dialer,
) (*Stream, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second}
	}
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	stream, err := HandshakeOver(conn, protocol, dcID, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

func HandshakeOver(
	raw io.ReadWriteCloser,
	protocol uint32,
	dcID int16,
	secret []byte,
) (*Stream, error) {
	hello, err := NewHandshake(protocol, dcID, secret)
	if err != nil {
		return nil, err
	}
	if _, err := raw.Write(hello.Wire); err != nil {
		return nil, fmt.Errorf("write handshake: %w", err)
	}
	return NewStream(raw, hello.Decrypt, hello.Encrypt), nil
}
