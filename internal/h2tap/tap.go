package h2tap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
)

const (
	maxHeaderBlock = 256 << 10
	maxHeaderList  = 1 << 20
	cancelCode     = 8
)

type Plan struct {
	Kind       string
	Code       uint32
	BeforeHdrs bool
	AfterBytes int64
	LastStream uint32
	CloseAfter time.Duration
	Debug      []byte
	Applied    *atomic.Bool
}

type planned struct {
	Plan
	sent int64
	done chan struct{}
}

// Conn leaves flow control and HTTP semantics to the HTTP server. It rewrites
// client HPACK separately from the server's encoder and serializes all writes.
type Conn struct {
	net.Conn
	closeOnce sync.Once
	done      chan struct{}
	incoming  chan []byte
	inject    chan []byte
	read      []byte

	mu           sync.Mutex
	plans        map[uint32]*planned
	dead         map[uint32]struct{}
	pending      []byte
	headerStream uint32
	resetNext    map[uint32]uint32
	closing      *time.Timer
	recvMax      atomic.Int32
	decoderLimit atomic.Uint32
	admitted     uint32
	cutoff       uint32
	hasCutoff    bool
}

func New(conn net.Conn) *Conn {
	c := &Conn{Conn: conn, done: make(chan struct{}), incoming: make(chan []byte, 1), inject: make(chan []byte, 64), plans: make(map[uint32]*planned), dead: make(map[uint32]struct{})}
	c.recvMax.Store(frameDefault)
	c.decoderLimit.Store(4096)
	go c.receive()
	return c
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.Conn.Close()
	})
	return err
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.read) == 0 {
		select {
		case c.read = <-c.inject:
		default:
			select {
			case c.read = <-c.inject:
			case b, ok := <-c.incoming:
				if !ok {
					return 0, io.EOF
				}
				c.read = b
			case <-c.done:
				return 0, net.ErrClosed
			}
		}
	}
	n := copy(p, c.read)
	c.read = c.read[n:]
	return n, nil
}

func (c *Conn) queue(b []byte) bool {
	select {
	case c.incoming <- b:
		return true
	case <-c.done:
		return false
	}
}

func (c *Conn) receive() {
	defer close(c.incoming)
	r := bufio.NewReader(c.Conn)
	preface := make([]byte, len(Preface))
	if _, err := io.ReadFull(r, preface); err != nil || !c.queue(preface) || string(preface) != Preface {
		return
	}
	dec := hpack.NewDecoder(4096, nil)
	dec.SetMaxStringLength(maxHeaderBlock)
	var block, encoded bytes.Buffer
	enc := hpack.NewEncoder(&encoded)
	enc.SetMaxDynamicTableSizeLimit(0)
	var lastOpened uint32
	for {
		h, data, err := readFrame(r, int(c.recvMax.Load()))
		if err != nil {
			if errors.Is(err, errFrameSize) {
				c.protocolError(lastOpened, 6)
			}
			return
		}
		if h.Type != frameHeaders {
			if h.Type == frameRST && h.Stream != 0 && len(data) == 4 {
				c.mu.Lock()
				c.forgetPlan(h.Stream)
				c.mu.Unlock()
			}
			if h.Type == frameSetting && h.Flags&flagAck == 0 && h.Stream == 0 && len(data)%6 == 0 {
				// A downstream RST may suppress server HEADERS: an unsent block
				// must never update the client's response HPACK table.
				found := false
				for i := 0; i < len(data); i += 6 {
					if binary.BigEndian.Uint16(data[i:]) == 1 {
						binary.BigEndian.PutUint32(data[i+2:], 0)
						found = true
					}
				}
				if !found {
					data = append(data, 0, 1, 0, 0, 0, 0)
				}
			}
			if !c.queue(appendFrame(nil, h.Type, h.Flags, h.Stream, data)) {
				return
			}
			continue
		}
		if h.Stream == 0 {
			c.protocolError(lastOpened, 1)
			return
		}
		block.Reset()
		first := h
		for {
			chunk, err := headerPayload(h, data)
			if err != nil || len(chunk) > maxHeaderBlock-block.Len() {
				c.protocolError(lastOpened, 1)
				return
			}
			block.Write(chunk)
			if h.Flags&flagEndHeaders != 0 {
				break
			}
			h, data, err = readFrame(r, int(c.recvMax.Load()))
			if err != nil || h.Type != frameCont || h.Stream != first.Stream {
				code := uint32(1)
				if errors.Is(err, errFrameSize) {
					code = 6
				}
				c.protocolError(lastOpened, code)
				return
			}
		}
		dec.SetAllowedMaxDynamicTableSize(c.decoderLimit.Load())
		encoded.Reset()
		size := 0
		dec.SetEmitEnabled(true)
		dec.SetEmitFunc(func(f hpack.HeaderField) {
			size += int(f.Size())
			if size > maxHeaderList {
				dec.SetEmitEnabled(false)
				return
			}
			if f.Name != StreamHeader {
				_ = enc.WriteField(f)
			}
		})
		if _, err := dec.Write(block.Bytes()); err != nil || dec.Close() != nil || size > maxHeaderList {
			c.protocolError(lastOpened, 9)
			return
		}
		c.mu.Lock()
		refused := c.hasCutoff && first.Stream > c.cutoff
		c.mu.Unlock()
		if refused {
			c.mu.Lock()
			err := c.send(wordFrame(frameRST, first.Stream, 7))
			c.mu.Unlock()
			if err != nil {
				return
			}
			continue
		}
		if first.Stream > lastOpened {
			lastOpened = first.Stream
			_ = enc.WriteField(hpack.HeaderField{Name: StreamHeader, Value: strconv.FormatUint(uint64(first.Stream), 10), Sensitive: true})
		}
		b := encoded.Bytes()
		out := make([]byte, 0, len(b)+frameHead*(len(b)/frameDefault+1))
		kind, flags := byte(frameHeaders), first.Flags&flagEndStream
		for len(b) > frameDefault {
			out = appendFrame(out, kind, flags, first.Stream, b[:frameDefault])
			kind, flags, b = frameCont, 0, b[frameDefault:]
		}
		if !c.queue(appendFrame(out, kind, flags|flagEndHeaders, first.Stream, b)) {
			return
		}
	}
}

func (c *Conn) protocolError(stream, code uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.goAway(stream, code, nil)
	_ = c.Close()
}

func (c *Conn) Arm(stream uint32, plan Plan) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	done := make(chan struct{})
	c.plans[stream] = &planned{Plan: plan, done: done}
	return done
}
func (c *Conn) ArmContext(ctx context.Context, stream uint32, plan Plan) <-chan struct{} {
	done := c.Arm(stream, plan)
	go func() {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.forgetPlan(stream)
			c.mu.Unlock()
		case <-done:
		case <-c.done:
		}
	}()
	return done
}

func (c *Conn) Done() <-chan struct{} { return c.done }

// AdmitUpstream records a stream before it can produce upstream side effects.
func (c *Conn) AdmitUpstream(stream uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasCutoff && stream > c.cutoff {
		return false
	}
	c.admitted = max(c.admitted, stream)
	return true
}

func (c *Conn) forgetPlan(stream uint32) {
	if p := c.plans[stream]; p != nil {
		delete(c.plans, stream)
		close(p.done)
	}
}

// Reset injects a reset at the next complete frame boundary.
func (c *Conn) Reset(stream, code uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 && c.headerStream == 0 {
		if err := c.reset(stream, code); err != nil {
			_ = c.Close()
		}
	} else {
		if c.resetNext == nil {
			c.resetNext = make(map[uint32]uint32)
		}
		c.resetNext[stream] = code
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := p
	if len(c.pending) != 0 {
		b = append(c.pending, p...)
		c.pending = nil
	}
	for len(b) >= frameHead {
		h := frameHeader(b)
		n := frameHead + h.Length
		if len(b) < n {
			break
		}
		if err := c.writeFrame(h, b[:n]); err != nil {
			_ = c.Close()
			return 0, err
		}
		switch {
		case h.Type == frameHeaders && h.Flags&flagEndHeaders == 0:
			c.headerStream = h.Stream
		case h.Type == frameCont && h.Stream == c.headerStream && h.Flags&flagEndHeaders != 0:
			c.headerStream = 0
		}
		if c.headerStream == 0 {
			for stream, code := range c.resetNext {
				if err := c.reset(stream, code); err != nil {
					_ = c.Close()
					return 0, err
				}
			}
			clear(c.resetNext)
		}
		b = b[n:]
	}
	if len(b) != 0 {
		c.pending = bytes.Clone(b)
	}
	return len(p), nil
}

func (c *Conn) writeFrame(h FrameHeader, raw []byte) error {
	body := raw[frameHead:]
	if h.Type == frameGoAway && len(body) >= 8 && c.hasCutoff {
		binary.BigEndian.PutUint32(body, min(binary.BigEndian.Uint32(body)&0x7fffffff, c.cutoff))
		c.cutoff = binary.BigEndian.Uint32(body)
	}
	if h.Type == frameSetting && h.Flags&flagAck == 0 {
		for b := body; len(b) >= 6; b = b[6:] {
			v := binary.BigEndian.Uint32(b[2:])
			switch binary.BigEndian.Uint16(b) {
			case 1:
				c.decoderLimit.Store(v)
			case 5:
				c.recvMax.Store(int32(v))
			}
		}
	}
	if _, dead := c.dead[h.Stream]; dead {
		if h.Type == frameData && h.Length != 0 {
			return c.enqueue(wordFrame(frameWindow, 0, uint32(h.Length)))
		}
		return nil
	}
	if h.Type == frameHeaders && c.hasCutoff && h.Stream > c.cutoff {
		return c.reset(h.Stream, 7)
	}
	if h.Type == frameHeaders {
		if p := c.plans[h.Stream]; p != nil && !p.BeforeHdrs && p.AfterBytes == 0 && p.Kind == "rst" {
			raw[4] &^= flagEndStream
		}
	}
	if p := c.plans[h.Stream]; p != nil {
		afterHeaders := !p.BeforeHdrs && p.AfterBytes == 0 && (h.Type == frameHeaders || h.Type == frameCont) && h.Flags&flagEndHeaders != 0
		fire := p.BeforeHdrs && h.Type == frameHeaders || afterHeaders || !p.BeforeHdrs && h.Type == frameData && p.sent+int64(h.Length) >= p.AfterBytes
		if fire {
			if afterHeaders {
				c.admitted = max(c.admitted, h.Stream)
			}
			if p.Kind == "goaway" {
				p.LastStream = max(p.LastStream, c.admitted)
				if c.hasCutoff {
					p.LastStream = min(p.LastStream, c.cutoff)
				}
			}
			delete(c.plans, h.Stream)
			defer close(p.done)
			if afterHeaders {
				if err := c.send(raw); err != nil {
					return err
				}
				raw = nil
			}
			if h.Type == frameData && (p.Kind == "rst" || h.Stream > p.LastStream) {
				n := int(clamp(p.AfterBytes-p.sent, 0, int64(h.Length)))
				if n != 0 {
					if err := c.send(appendFrame(nil, frameData, 0, h.Stream, body[:n])); err != nil {
						return err
					}
				}
				if n != h.Length {
					if err := c.enqueue(wordFrame(frameWindow, 0, uint32(h.Length-n))); err != nil {
						return err
					}
				}
			}
			if p.Kind == "rst" {
				if err := c.send(wordFrame(frameRST, h.Stream, p.Code)); err != nil {
					return err
				}
				if p.Applied != nil {
					p.Applied.Store(true)
				}
				return c.kill(h.Stream)
			}
			last := max(p.LastStream, c.admitted)
			if c.hasCutoff {
				last = min(last, c.cutoff)
			}
			c.cutoff, c.hasCutoff = last, true
			if err := c.goAway(last, p.Code, p.Debug); err != nil {
				return err
			}
			if p.Applied != nil {
				p.Applied.Store(true)
			}
			if c.closing == nil {
				c.closing = time.AfterFunc(p.CloseAfter, func() { _ = c.Close() })
			}
			if h.Stream > last {
				return c.kill(h.Stream)
			}
		} else if h.Type == frameData {
			p.sent += int64(h.Length)
		}
		if h.Flags&flagEndStream != 0 && (h.Type == frameData || h.Type == frameHeaders && (p.AfterBytes != 0 || h.Flags&flagEndHeaders != 0)) || h.Type == frameRST {
			c.forgetPlan(h.Stream)
		}
	}
	if h.Type == frameHeaders {
		c.admitted = max(c.admitted, h.Stream)
	}
	return c.send(raw)
}

func clamp(v, low, high int64) int64 { return max(low, min(high, v)) }

func (c *Conn) reset(stream, code uint32) error {
	c.forgetPlan(stream)
	if _, dead := c.dead[stream]; dead {
		return nil
	}
	if err := c.send(wordFrame(frameRST, stream, code)); err != nil {
		return err
	}
	return c.kill(stream)
}

func (c *Conn) kill(stream uint32) error {
	c.dead[stream] = struct{}{}
	if len(c.dead) == 1024 && c.closing == nil {
		if err := c.goAway(stream, 0, nil); err != nil {
			return err
		}
		c.closing = time.AfterFunc(100*time.Millisecond, func() { _ = c.Close() })
	}
	return c.enqueue(wordFrame(frameRST, stream, cancelCode))
}

func (c *Conn) enqueue(b []byte) error {
	select {
	case c.inject <- b:
		return nil
	default:
		return errors.New("HTTP/2 injection queue full")
	}
}

func (c *Conn) goAway(stream, code uint32, debug []byte) error {
	stream = max(stream, c.admitted)
	if c.hasCutoff {
		stream = min(stream, c.cutoff)
	}
	c.cutoff, c.hasCutoff = stream, true
	body := binary.BigEndian.AppendUint32(nil, stream)
	body = binary.BigEndian.AppendUint32(body, code)
	return c.send(appendFrame(nil, frameGoAway, 0, 0, append(body, debug...)))
}

func (c *Conn) send(b []byte) error {
	for len(b) != 0 {
		n, err := c.Conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
