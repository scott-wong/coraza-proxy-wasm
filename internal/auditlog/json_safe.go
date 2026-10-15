// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// jsonSafeFormatter is a drop-in replacement for coraza's built-in "json"
// audit-log formatter that never hands a coraza type to encoding/json.
//
// Why this exists: coraza's formatter marshals its internal Log struct, whose
// type graph contains interface-typed values (Messages is a
// []plugintypes.AuditLogMessage, request arguments and message data are
// reached through interfaces). Building an encoder for such a graph makes
// encoding/json ask the reflect package whether the type implements
// json.Marshaler, and TinyGo only grew a working implementation of that
// question in v0.41:
//
//	panic: reflect: unimplemented: AssignableTo with interface
//
// TinyGo v0.41+ cannot be used for this plugin (its wasm module dies in
// runtime.initAll at _start), so the audit-log write - which happens inside the
// request path once a rule matches and SecAuditEngine is enabled - would trap
// the whole module.
//
// This formatter therefore snapshots the audit log into concrete structs
// mirroring coraza's JSON schema (field order and tags included) and marshals
// only those. The output is byte-for-byte identical to coraza's own "json"
// formatter; json_safe_test.go asserts that by comparing both formatters on
// the same audit logs.
type jsonSafeFormatter struct{}

var _ plugintypes.AuditLogFormatter = jsonSafeFormatter{}

func (jsonSafeFormatter) MIME() string {
	return "application/json; charset=utf-8"
}

func (jsonSafeFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	return snapshotAuditLog(al).encode(), nil
}

// isNil reports whether v is nil, including the typed nil case: a non-nil
// interface holding a nil pointer, which is what coraza's optional audit log
// parts look like when unset (RuleSeverity-style interfaces returned by
// accessors). Calling a method on such a value panics, while encoding/json
// renders it as null, so the distinction matters here.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// snapshotJSONLog mirrors coraza's internal auditlog.Log. Field order and JSON
// tags must match coraza's structs exactly.
type snapshotJSONLog struct {
	Transaction snapshotJSONTransaction `json:"transaction"`
	Messages    []snapshotJSONMessage   `json:"messages,omitempty"`
}

type snapshotJSONTransaction struct {
	Timestamp       string                `json:"timestamp"`
	UnixTimestamp   int64                 `json:"unix_timestamp"`
	ID              string                `json:"id"`
	ClientIP        string                `json:"client_ip"`
	ClientPort      int                   `json:"client_port"`
	HostIP          string                `json:"host_ip"`
	HostPort        int                   `json:"host_port"`
	ServerID        string                `json:"server_id"`
	Request         *snapshotJSONRequest  `json:"request,omitempty"`
	Response        *snapshotJSONResponse `json:"response,omitempty"`
	Producer        *snapshotJSONProducer `json:"producer,omitempty"`
	HighestSeverity string                `json:"highest_severity"`
	IsInterrupted   bool                  `json:"is_interrupted"`
}

type snapshotJSONRequest struct {
	Method      string              `json:"method"`
	Protocol    string              `json:"protocol"`
	URI         string              `json:"uri"`
	HTTPVersion string              `json:"http_version"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	Files       []*snapshotJSONFile `json:"files"`
	// Args holds coraza's argument collection pre-rendered. It has no exported
	// fields, so it always marshals to {} (or null when unset).
	Args   []byte `json:"args"`
	Length int32  `json:"length"`
}

type snapshotJSONFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

type snapshotJSONResponse struct {
	Protocol string              `json:"protocol"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body"`
}

type snapshotJSONProducer struct {
	Connector  string   `json:"connector"`
	Version    string   `json:"version"`
	Server     string   `json:"server"`
	RuleEngine string   `json:"rule_engine"`
	Stopwatch  string   `json:"stopwatch"`
	Rulesets   []string `json:"rulesets"`
}

type snapshotJSONMessage struct {
	Actionset    string                   `json:"actionset"`
	Message      string                   `json:"message"`
	ErrorMessage string                   `json:"error_message"`
	Data         *snapshotJSONMessageData `json:"data"`
}

type snapshotJSONMessageData struct {
	File     string             `json:"file"`
	Line     int                `json:"line"`
	ID       int                `json:"id"`
	Rev      string             `json:"rev"`
	Msg      string             `json:"msg"`
	Data     string             `json:"data"`
	Severity types.RuleSeverity `json:"severity"`
	Ver      string             `json:"ver"`
	Maturity int                `json:"maturity"`
	Accuracy int                `json:"accuracy"`
	Tags     []string           `json:"tags"`
	Raw      string             `json:"raw"`
}

// errorMessager matches coraza's internal auditLogWithErrMesg assertion: the
// public AuditLogMessage interface does not expose ErrorMessage() yet, so we
// probe for it the same way coraza does.
type errorMessager interface{ ErrorMessage() string }

func snapshotAuditLog(al plugintypes.AuditLog) snapshotJSONLog {
	tx := al.Transaction()
	out := snapshotJSONLog{
		Transaction: snapshotJSONTransaction{
			Timestamp:       tx.Timestamp(),
			UnixTimestamp:   tx.UnixTimestamp(),
			ID:              tx.ID(),
			ClientIP:        tx.ClientIP(),
			ClientPort:      tx.ClientPort(),
			HostIP:          tx.HostIP(),
			HostPort:        tx.HostPort(),
			ServerID:        tx.ServerID(),
			HighestSeverity: tx.HighestSeverity(),
			IsInterrupted:   tx.IsInterrupted(),
		},
	}

	if tx.HasRequest() {
		req := tx.Request()
		sReq := &snapshotJSONRequest{
			Method:      req.Method(),
			Protocol:    req.Protocol(),
			URI:         req.URI(),
			HTTPVersion: req.HTTPVersion(),
			Headers:     req.Headers(),
			Body:        req.Body(),
			Args:        []byte("null"),
			Length:      req.Length(),
		}
		if files := req.Files(); !isNil(files) {
			sReq.Files = make([]*snapshotJSONFile, 0, len(files))
			for _, f := range files {
				if isNil(f) {
					sReq.Files = append(sReq.Files, nil)
					continue
				}
				sReq.Files = append(sReq.Files, &snapshotJSONFile{
					Name: f.Name(),
					Size: f.Size(),
					Mime: f.Mime(),
				})
			}
		}
		if args := req.Args(); args != nil {
			// The collection has no exported fields, so this is what
			// encoding/json produces for it in coraza's own formatter.
			sReq.Args = []byte("{}")
		}
		out.Transaction.Request = sReq
	}

	if tx.HasResponse() {
		res := tx.Response()
		out.Transaction.Response = &snapshotJSONResponse{
			Protocol: res.Protocol(),
			Status:   res.Status(),
			Headers:  res.Headers(),
			Body:     res.Body(),
		}
	}

	if p := tx.Producer(); p != nil {
		out.Transaction.Producer = &snapshotJSONProducer{
			Connector:  p.Connector(),
			Version:    p.Version(),
			Server:     p.Server(),
			RuleEngine: p.RuleEngine(),
			Stopwatch:  p.Stopwatch(),
			Rulesets:   p.Rulesets(),
		}
	}

	messages := al.Messages()
	if len(messages) > 0 {
		out.Messages = make([]snapshotJSONMessage, 0, len(messages))
		for _, m := range messages {
			sMsg := snapshotJSONMessage{
				Actionset: m.Actionset(),
				Message:   m.Message(),
			}
			if em, ok := m.(errorMessager); ok {
				sMsg.ErrorMessage = em.ErrorMessage()
			}
			if data := m.Data(); !isNil(data) {
				sMsg.Data = &snapshotJSONMessageData{
					File:     data.File(),
					Line:     data.Line(),
					ID:       data.ID(),
					Rev:      data.Rev(),
					Msg:      data.Msg(),
					Data:     data.Data(),
					Severity: data.Severity(),
					Ver:      data.Ver(),
					Maturity: data.Maturity(),
					Accuracy: data.Accuracy(),
					Tags:     data.Tags(),
					Raw:      data.Raw(),
				}
			}
			out.Messages = append(out.Messages, sMsg)
		}
	}

	return out
}

// The encoder below replaces encoding/json for the wasm build.
//
// encoding/json cannot be used at all there: its encoder construction asks the
// reflect package whether a type implements json.Marshaler, and TinyGo answers
// that question by panicking unless it happens to fold the answer at compile
// time. In this plugin's binary it does not: even json.Marshal(int64(1)) traps
// the module. So formatting is done by hand, byte-for-byte matching what
// encoding/json (escapeHTML mode, the default for json.Marshal) produces for
// the snapshot structs above. json_safe_test.go checks that equivalence on the
// host, where encoding/json does work.
type jsonEncoder struct {
	buf []byte
}

func (e *jsonEncoder) raw(s string) {
	e.buf = append(e.buf, s...)
}

func (e *jsonEncoder) int64(v int64) {
	e.buf = strconv.AppendInt(e.buf, v, 10)
}

func (e *jsonEncoder) int(v int) {
	e.buf = strconv.AppendInt(e.buf, int64(v), 10)
}

func (e *jsonEncoder) bool(v bool) {
	e.buf = strconv.AppendBool(e.buf, v)
}

const hexDigits = "0123456789abcdef"

// string appends s as a JSON string, escaping exactly like encoding/json does
// with escapeHTML: ", \ and the control characters, plus <, > and & as \u00xx,
// U+2028/U+2029 as \u2028/\u2029 and invalid UTF-8 as U+FFFD.
func (e *jsonEncoder) string(s string) {
	e.buf = append(e.buf, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&' {
				i++
				continue
			}
			if start < i {
				e.buf = append(e.buf, s[start:i]...)
			}
			switch b {
			case '\\', '"':
				e.buf = append(e.buf, '\\', b)
			case '\n':
				e.buf = append(e.buf, '\\', 'n')
			case '\r':
				e.buf = append(e.buf, '\\', 'r')
			case '\t':
				e.buf = append(e.buf, '\\', 't')
			default:
				// Remaining control characters and HTML-sensitive ones:
				// encoding/json writes \u00 followed by the byte's hex digits.
				e.buf = append(e.buf, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.buf = append(e.buf, s[start:i]...)
			}
			e.buf = append(e.buf, '\\', 'u', 'f', 'f', 'f', 'd')
			i += size
			start = i
			continue
		}
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.buf = append(e.buf, s[start:i]...)
			}
			e.buf = append(e.buf, '\\', 'u', '2', '0', '2', hexDigits[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.buf = append(e.buf, s[start:]...)
	}
	e.buf = append(e.buf, '"')
}

// stringMap writes a map[string][]string the way encoding/json does: keys
// sorted, nil maps as null, empty maps as {}.
func (e *jsonEncoder) stringMap(m map[string][]string) {
	if m == nil {
		e.raw("null")
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	e.raw("{")
	for i, k := range keys {
		if i > 0 {
			e.raw(",")
		}
		e.string(k)
		e.raw(":")
		e.stringSlice(m[k])
	}
	e.raw("}")
}

func (e *jsonEncoder) stringSlice(values []string) {
	if values == nil {
		e.raw("null")
		return
	}
	e.raw("[")
	for i, v := range values {
		if i > 0 {
			e.raw(",")
		}
		e.string(v)
	}
	e.raw("]")
}

func (l snapshotJSONLog) encode() []byte {
	e := &jsonEncoder{}
	e.raw(`{"transaction":`)
	l.Transaction.encode(e)
	if len(l.Messages) > 0 { // json:"...,omitempty"
		e.raw(`,"messages":[`)
		for i, m := range l.Messages {
			if i > 0 {
				e.raw(",")
			}
			m.encode(e)
		}
		e.raw("]")
	}
	e.raw("}")
	return e.buf
}

func (t snapshotJSONTransaction) encode(e *jsonEncoder) {
	e.raw(`{"timestamp":`)
	e.string(t.Timestamp)
	e.raw(`,"unix_timestamp":`)
	e.int64(t.UnixTimestamp)
	e.raw(`,"id":`)
	e.string(t.ID)
	e.raw(`,"client_ip":`)
	e.string(t.ClientIP)
	e.raw(`,"client_port":`)
	e.int(t.ClientPort)
	e.raw(`,"host_ip":`)
	e.string(t.HostIP)
	e.raw(`,"host_port":`)
	e.int(t.HostPort)
	e.raw(`,"server_id":`)
	e.string(t.ServerID)
	if t.Request != nil { // json:"...,omitempty"
		e.raw(`,"request":`)
		t.Request.encode(e)
	}
	if t.Response != nil {
		e.raw(`,"response":`)
		t.Response.encode(e)
	}
	if t.Producer != nil {
		e.raw(`,"producer":`)
		t.Producer.encode(e)
	}
	e.raw(`,"highest_severity":`)
	e.string(t.HighestSeverity)
	e.raw(`,"is_interrupted":`)
	e.bool(t.IsInterrupted)
	e.raw("}")
}

func (r *snapshotJSONRequest) encode(e *jsonEncoder) {
	e.raw(`{"method":`)
	e.string(r.Method)
	e.raw(`,"protocol":`)
	e.string(r.Protocol)
	e.raw(`,"uri":`)
	e.string(r.URI)
	e.raw(`,"http_version":`)
	e.string(r.HTTPVersion)
	e.raw(`,"headers":`)
	e.stringMap(r.Headers)
	e.raw(`,"body":`)
	e.string(r.Body)
	e.raw(`,"files":`)
	if r.Files == nil {
		e.raw("null")
	} else {
		e.raw("[")
		for i, f := range r.Files {
			if i > 0 {
				e.raw(",")
			}
			if f == nil {
				e.raw("null")
				continue
			}
			f.encode(e)
		}
		e.raw("]")
	}
	e.raw(`,"args":`)
	e.buf = append(e.buf, r.Args...)
	e.raw(`,"length":`)
	e.int(int(r.Length))
	e.raw("}")
}

func (f *snapshotJSONFile) encode(e *jsonEncoder) {
	e.raw(`{"name":`)
	e.string(f.Name)
	e.raw(`,"size":`)
	e.int64(f.Size)
	e.raw(`,"mime":`)
	e.string(f.Mime)
	e.raw("}")
}

func (r *snapshotJSONResponse) encode(e *jsonEncoder) {
	e.raw(`{"protocol":`)
	e.string(r.Protocol)
	e.raw(`,"status":`)
	e.int(r.Status)
	e.raw(`,"headers":`)
	e.stringMap(r.Headers)
	e.raw(`,"body":`)
	e.string(r.Body)
	e.raw("}")
}

func (p *snapshotJSONProducer) encode(e *jsonEncoder) {
	e.raw(`{"connector":`)
	e.string(p.Connector)
	e.raw(`,"version":`)
	e.string(p.Version)
	e.raw(`,"server":`)
	e.string(p.Server)
	e.raw(`,"rule_engine":`)
	e.string(p.RuleEngine)
	e.raw(`,"stopwatch":`)
	e.string(p.Stopwatch)
	e.raw(`,"rulesets":`)
	e.stringSlice(p.Rulesets)
	e.raw("}")
}

func (m snapshotJSONMessage) encode(e *jsonEncoder) {
	e.raw(`{"actionset":`)
	e.string(m.Actionset)
	e.raw(`,"message":`)
	e.string(m.Message)
	e.raw(`,"error_message":`)
	e.string(m.ErrorMessage)
	e.raw(`,"data":`)
	if m.Data == nil {
		e.raw("null")
	} else {
		m.Data.encode(e)
	}
	e.raw("}")
}

func (d *snapshotJSONMessageData) encode(e *jsonEncoder) {
	e.raw(`{"file":`)
	e.string(d.File)
	e.raw(`,"line":`)
	e.int(d.Line)
	e.raw(`,"id":`)
	e.int(d.ID)
	e.raw(`,"rev":`)
	e.string(d.Rev)
	e.raw(`,"msg":`)
	e.string(d.Msg)
	e.raw(`,"data":`)
	e.string(d.Data)
	e.raw(`,"severity":`)
	e.int(int(d.Severity))
	e.raw(`,"ver":`)
	e.string(d.Ver)
	e.raw(`,"maturity":`)
	e.int(d.Maturity)
	e.raw(`,"accuracy":`)
	e.int(d.Accuracy)
	e.raw(`,"tags":`)
	e.stringSlice(d.Tags)
	e.raw(`,"raw":`)
	e.string(d.Raw)
	e.raw("}")
}
