package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxMessageBytes = 64 * 1024

type Message struct {
	ProtocolVersion int             `json:"protocol_version"`
	Type            string          `json:"type"`
	ID              string          `json:"id"`
	Payload         json.RawMessage `json:"payload"`
}

func strictJSON(data []byte, target any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting exceeded")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					name, ok := k.(string)
					if !ok || seen[name] {
						return errors.New("duplicate JSON property")
					}
					seen[name] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return errors.New("invalid JSON")
			}
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	typ := reflect.TypeOf(target)
	if typ != nil && typ.Kind() == reflect.Pointer && typ.Elem().Kind() == reflect.Struct {
		allowed := map[string]bool{}
		for i := 0; i < typ.Elem().NumField(); i++ {
			tag := strings.Split(typ.Elem().Field(i).Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				allowed[tag] = true
			}
		}
		var properties map[string]json.RawMessage
		if json.Unmarshal(data, &properties) != nil || properties == nil {
			return errors.New("JSON object required")
		}
		for name := range properties {
			if !allowed[name] {
				return errors.New("unknown JSON property")
			}
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return errors.New("invalid JSON properties")
	}
	return nil
}
func ReadMessage(r *bufio.Reader) (Message, error) {
	var data []byte
	for {
		part, prefix, e := r.ReadLine()
		if e != nil {
			return Message{}, e
		}
		if len(data)+len(part) > MaxMessageBytes {
			return Message{}, errors.New("message too large")
		}
		data = append(data, part...)
		if !prefix {
			break
		}
	}
	var m Message
	if e := strictJSON(data, &m); e != nil {
		return Message{}, e
	}
	if m.ProtocolVersion != 1 || m.ID == "" || len(m.ID) > 64 || m.Type == "" || len(m.Type) > 40 || len(m.Payload) == 0 || m.Payload[0] != '{' {
		return Message{}, errors.New("invalid envelope")
	}
	return m, nil
}
func writeMessage(w io.Writer, kind, id string, payload any) error {
	p, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	b, e := json.Marshal(Message{1, kind, id, p})
	if e != nil {
		return e
	}
	if len(b) > MaxMessageBytes {
		return errors.New("reply too large")
	}
	b = append(b, '\n')
	_, e = w.Write(b)
	return e
}

type manager struct {
	mu         sync.Mutex
	s          *Session
	cancel     context.CancelFunc
	generation uint64
	connecting bool
	checking   bool
}

func (m *manager) stop() {
	m.mu.Lock()
	m.generation++
	if m.cancel != nil {
		m.cancel()
	}
	s := m.s
	m.s = nil
	m.connecting = false
	m.checking = false
	m.mu.Unlock()
	if s != nil {
		s.Close()
	}
}
func (m *manager) status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s != nil {
		return m.s.Status()
	}
	if m.connecting {
		return Status{State: "Connecting", Message: "Waiting for handshake and tunnel probe"}
	}
	return Status{State: "Stopped", Message: "Stopped"}
}

// Serve runs protocol-only stdio control. EOF cancels pending connect and closes
// the owned stack/listeners. No real configuration is accepted outside the pipe.
func Serve(in io.Reader, out io.Writer) error {
	var m manager
	var tasks sync.WaitGroup
	defer func() { m.stop(); tasks.Wait() }()
	var output sync.Mutex
	send := func(kind, id string, p any) error {
		output.Lock()
		defer output.Unlock()
		return writeMessage(out, kind, id, p)
	}
	fail := func(id, code string) { _ = send("error", id, map[string]string{"code": code}) }
	type readResult struct {
		msg Message
		err error
	}
	incoming := make(chan readResult, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		r := bufio.NewReaderSize(in, 4096)
		for {
			msg, e := ReadMessage(r)
			select {
			case incoming <- readResult{msg, e}:
			case <-done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	for {
		v := <-incoming
		if v.err == io.EOF {
			return nil
		}
		if v.err != nil {
			return errors.New("invalid control stream")
		}
		msg := v.msg
		switch msg.Type {
		case "hello", "get_status", "disconnect", "shutdown", "check_tunnel":
			var empty map[string]json.RawMessage
			if strictJSON(msg.Payload, &empty) != nil || empty == nil || len(empty) != 0 {
				fail(msg.ID, "invalid_payload")
				continue
			}
			switch msg.Type {
			case "check_tunnel":
				m.mu.Lock()
				session := m.s
				if session == nil || m.checking {
					m.mu.Unlock()
					fail(msg.ID, "not_connected")
					continue
				}
				m.checking = true
				generation := m.generation
				m.mu.Unlock()
				tasks.Add(1)
				go func(id string) {
					defer tasks.Done()
					ctx, cancel := context.WithTimeout(session.ctx, 10*time.Second)
					defer cancel()
					e := session.CheckTunnel(ctx)
					m.mu.Lock()
					if generation != m.generation {
						m.mu.Unlock()
						fail(id, "connection_cancelled")
						return
					}
					m.checking = false
					if e != nil {
						m.generation++
						m.s = nil
					}
					m.mu.Unlock()
					if e != nil {
						session.Close()
						_ = send("status", id, Status{State: "Error", Message: "Tunnel verification failed; listeners closed"})
					} else {
						_ = send("status", id, session.Status())
					}
				}(msg.ID)
			case "hello":
				if e := send("hello", msg.ID, map[string]any{"protocol_version": 1, "core_version": "awg-local-core-0.1.0", "commit": "independent", "capabilities": []string{"real_core", "stdio", "socks5", "http", "amneziawg"}}); e != nil {
					return e
				}
			case "get_status":
				if e := send("status", msg.ID, m.status()); e != nil {
					return e
				}
			case "disconnect":
				m.stop()
				if e := send("status", msg.ID, m.status()); e != nil {
					return e
				}
			case "shutdown":
				m.stop()
				return send("shutdown", msg.ID, struct{}{})
			}
		case "validate_config":
			var p struct {
				Config string `json:"config"`
			}
			if strictJSON(msg.Payload, &p) != nil || ValidateConfig(p.Config) != nil {
				fail(msg.ID, "invalid_config")
				continue
			}
			if e := send("validated", msg.ID, map[string]bool{"valid": true}); e != nil {
				return e
			}
		case "connect":
			var o ConnectOptions
			if strictJSON(msg.Payload, &o) != nil {
				fail(msg.ID, "invalid_payload")
				continue
			}
			if o.TimeoutSeconds == 0 {
				o.TimeoutSeconds = 15
			}
			if o.TimeoutSeconds < 1 || o.TimeoutSeconds > 60 {
				fail(msg.ID, "invalid_timeout")
				continue
			}
			m.mu.Lock()
			if m.connecting || m.s != nil {
				m.mu.Unlock()
				fail(msg.ID, "already_active")
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.TimeoutSeconds)*time.Second)
			m.cancel = cancel
			m.connecting = true
			m.generation++
			generation := m.generation
			m.mu.Unlock()
			tasks.Add(1)
			go func(id string, opts ConnectOptions) {
				defer tasks.Done()
				defer cancel()
				s, e := Connect(ctx, opts)
				opts.Config = ""
				m.mu.Lock()
				if generation != m.generation {
					m.mu.Unlock()
					if s != nil {
						s.Close()
					}
					fail(id, "connection_cancelled")
					return
				}
				m.connecting = false
				if e == nil {
					m.s = s
				}
				m.mu.Unlock()
				if e != nil {
					code := "connect_failed"
					if errors.Is(e, ErrConfig) {
						code = "invalid_config"
					}
					if strings.Contains(e.Error(), "port unavailable") {
						code = "port_unavailable"
					}
					fail(id, code)
					return
				}
				_ = send("status", id, s.Status())
			}(msg.ID, o)
		default:
			fail(msg.ID, "unsupported_command")
		}
	}
}
