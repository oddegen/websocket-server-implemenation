package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
)

type Conn interface {
	Close() error
}

type Ws struct {
	conn       Conn
	buf        *bufio.ReadWriter
	headers    http.Header
	statusCode uint16
}

func New(w http.ResponseWriter, r *http.Request) (*Ws, error) {
	hi, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil
	}

	conn, bufnr, err := hi.Hijack()
	if err != nil {
		return nil, err
	}

	return &Ws{
		conn:       conn,
		buf:        bufnr,
		headers:    r.Header,
		statusCode: 1000,
	}, nil

}

// GET /chat HTTP/1.1
// Host: server.example.com
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
// Origin: http://example.com
// Sec-WebSocket-Protocol: chat, superchat
// Sec-WebSocket-Version: 13

// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
// Sec-WebSocket-Protocol: chat

// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

// For this header field, the server has to take the value (as present
// in the header field, e.g., the base64-encoded [RFC4648] version minus
// any leading and trailing whitespace) and concatenate this with the
// Globally Unique Identifier (GUID, [RFC4122]) "258EAFA5-E914-47DA-
// 95CA-C5AB0DC85B11" in string form, which is unlikely to be used by
// network endpoints that do not understand the WebSocket Protocol.  A
// SHA-1 hash (160 bits) [FIPS.180-3], base64-encoded (see Section 4 of
// [RFC4648]), of this concatenation is then returned in the server's
// handshake.

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	key = strings.TrimSpace(key)
	hash := sha1.New()
	hash.Write([]byte(key))
	hash.Write([]byte(GUID))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func (ws *Ws) Handshake() error {
	key := ws.headers.Get("Sec-WebSocket-Key")
	hash := wsAccept(string(key))

	header := []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + hash,
		"",
		"",
	}

	return ws.write([]byte(strings.Join(header, "\r\n")))

}

func (ws *Ws) write(data []byte) error {
	if _, err := ws.buf.Write(data); err != nil {
		return err
	}
	return ws.buf.Flush()
}

func (ws *Ws) Recv() (*Frame, error) {
	var b byte

	frame := &Frame{}

	b, err := ws.buf.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.FIN = ((b >> 7) & 1) != 0
	for i := 0; i < 3; i++ {
		frame.RSV[i] = ((b >> (6 - i)) & 1) != 0
	}
	frame.Opcode = Opcode(b & 0x0F)

	b, err = ws.buf.ReadByte()
	if err != nil {
		return nil, err
	}

	frame.MASK = (b & 0x80) != 0

	length := uint64(b & 0x7F)
	var n int = 0

	if length == 126 {
		n = 2
	} else if length == 127 {
		n = 8
	}

	for i := 0; i < n; i++ {
		b, err = ws.buf.ReadByte()
		if err != nil {
			return nil, err
		}

		if n == 8 && i == 0 {
			b = b & 0x7F
		}

		frame.Length = frame.Length*256 + uint64(b)
	}

	if frame.MASK {
		for i := 0; i < 4; i++ {
			b, err := ws.buf.ReadByte()
			if err != nil {
				return nil, err
			}

			frame.MSKEY = append(frame.MSKEY, b)
		}
	}

	var payload []byte
	for i := 0; i < int(frame.Length); i++ {
		b, err = ws.buf.ReadByte()
		if err != nil {
			return nil, err
		}
		payload = append(payload, b)
	}

	if frame.MASK {
		// j                   = i MOD 4
		// transformed-octet-i = original-octet-i XOR masking-key-octet-j
		for i := uint64(0); i < frame.Length; i++ {
			payload[i] ^= frame.MSKEY[i%4]
		}
	}

	frame.Data = payload
	return frame, nil

}

func (ws *Ws) Send(f *Frame) error {
	var header []byte
	var b byte

	if f.FIN {
		b |= 0x80
	}

	for i := 0; i < 3; i++ {
		if f.RSV[i] {
			b = (b << (i + 1)) | 0x80
		}
	}
	b |= byte(f.Opcode)

	header = append(header, b)

	// Server
	b = 0

	var n int = 0

	if f.Length <= 125 {
		b |= byte(f.Length)
	} else if f.Length < (1 << 16) {
		b |= 126
		n = 2
	} else {
		b |= 127
		n = 8
	}
	header = append(header, b)

	for i := n - 1; i >= 0; i-- {
		b = byte(f.Length >> (8 * i) & 0xFF)
		header = append(header, b)
	}

	header = append(header, f.Data...)

	return ws.write(header)

}

func (ws *Ws) Close() error {
	f := new(Frame)
	f.Opcode = ConnectionClose
	f.Length = 2

	f.Data = make([]byte, 2)
	f.Data[0] = byte(ws.statusCode >> 1)
	f.Data[2] = byte(ws.statusCode)

	if err := ws.Send(f); err != nil {
		return err
	}

	return ws.conn.Close()
}
