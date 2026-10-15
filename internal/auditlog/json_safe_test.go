// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

// captureWriter records the audit logs it is handed together with the output of
// the formatter coraza selected (its own "json" formatter, when running on the
// host), so tests can compare it with jsonSafeFormatter's output.
type captureWriter struct {
	formatter plugintypes.AuditLogFormatter
	logs      []plugintypes.AuditLog
	reference [][]byte
}

func (w *captureWriter) Init(cfg plugintypes.AuditLogConfig) error {
	w.formatter = cfg.Formatter
	return nil
}

func (w *captureWriter) Write(al plugintypes.AuditLog) error {
	out, err := w.formatter.Format(al)
	if err != nil {
		return err
	}
	w.logs = append(w.logs, al)
	w.reference = append(w.reference, out)
	return nil
}

func (w *captureWriter) Close() error { return nil }

// TestJSONSafeFormatterMatchesCoraza asserts that the TinyGo-safe formatter is
// a byte-for-byte drop-in replacement for coraza's "json" audit log format.
//
// The reference output is produced by coraza's own formatter (selected through
// SecAuditLogFormat json on a host build), fed with the very same audit log.
func TestJSONSafeFormatterMatchesCoraza(t *testing.T) {
	var captured *captureWriter
	plugins.RegisterAuditLogWriter("capture_json_test", func() plugintypes.AuditLogWriter {
		captured = &captureWriter{}
		return captured
	})

	tests := []struct {
		name       string
		directives string
		drive      func(tx types.Transaction)
	}{
		{
			name: "deny with rule metadata and no data",
			directives: `
SecRuleEngine On
SecRule ARGS "@contains attack" "id:1001,phase:2,deny,log,msg:'attack detected',severity:'CRITICAL',rev:'2',ver:'OWASP_CRS/4.14.0',tag:'attack-xss',logdata:'matched %{MATCHED_VAR}'"
`,
			drive: func(tx types.Transaction) {
				tx.ProcessURI("/hello?foo=attack", "GET", "HTTP/1.1")
				tx.AddRequestHeader("User-Agent", "test")
				tx.ProcessRequestHeaders()
				_, err := tx.ProcessRequestBody()
				require.NoError(t, err)
			},
		},
		{
			name: "clean transaction with response body",
			directives: `
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@contains secret" "id:1002,phase:4,deny,log,msg:'leak',severity:'WARNING'"
`,
			drive: func(tx types.Transaction) {
				tx.ProcessURI("/", "GET", "HTTP/1.1")
				tx.ProcessRequestHeaders()
				tx.AddResponseHeader("Content-Type", "text/plain")
				tx.ProcessResponseHeaders(200, "HTTP/1.1")
				_, _, err := tx.WriteResponseBody([]byte("a secret value"))
				require.NoError(t, err)
				_, err = tx.ProcessResponseBody()
				require.NoError(t, err)
			},
		},
		{
			name: "escaped and multi-byte field values",
			directives: `
SecRuleEngine On
SecRule ARGS "@contains attack" "id:1004,phase:2,deny,log,msg:'weird <value> & \"quotes\"',logdata:'tab\there\nnewline \u2028 sep'"
`,
			drive: func(tx types.Transaction) {
				// URI, header values and body deliberately contain characters
				// encoding/json escapes differently from a naive writer:
				// HTML-sensitive bytes, control characters, U+2028 and invalid
				// UTF-8.
				tx.ProcessURI("/hello?x=<script>&y=\"q\"&z=attack", "GET", "HTTP/1.1")
				tx.AddRequestHeader("User-Agent", "evi\tl\n<>&\u2028\xff\xfe")
				tx.AddRequestHeader("X-Unicode", "\u4e2d\u6587 \U0001F600")
				tx.ProcessRequestHeaders()
				_, err := tx.ProcessRequestBody()
				require.NoError(t, err)
			},
		},
		{
			name: "phase 1 deny without request body",
			directives: `
SecRuleEngine On
SecRule REQUEST_HEADERS:User-Agent "@contains evil" "id:1003,phase:1,deny,log,msg:'bad agent'"
`,
			drive: func(tx types.Transaction) {
				tx.ProcessURI("/", "GET", "HTTP/1.1")
				tx.AddRequestHeader("User-Agent", "evil")
				tx.ProcessRequestHeaders()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			captured = nil
			directives := tc.directives + `
SecRequestBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus ".*"
SecAuditLogType capture_json_test
SecAuditLogFormat json
SecAuditLogParts ABCDEFHZ
`
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
			require.NoError(t, err)

			tx := waf.NewTransaction()
			tx.ProcessConnection("127.0.0.1", 8080, "10.0.0.1", 12345)
			tc.drive(tx)
			tx.ProcessLogging()
			require.NoError(t, tx.Close())

			require.NotNil(t, captured, "audit log was not written")
			require.NotEmpty(t, captured.logs, "audit log was not written")

			for i, al := range captured.logs {
				ours, err := jsonSafeFormatter{}.Format(al)
				require.NoError(t, err)
				require.Equal(t, string(captured.reference[i]), string(ours),
					"jsonSafeFormatter output differs from coraza's json formatter")
				if tc.name == "escaped and multi-byte field values" {
					// Guard against the corpus silently disappearing from the
					// audit log (which would make the equality above vacuous
					// for escaping): these escapes only appear if the values
					// reached the log.
					require.Contains(t, string(ours), `\u003c`, "HTML-sensitive characters were not exercised")
					require.Contains(t, string(ours), `\u2028`, "U+2028 was not exercised")
					require.Contains(t, string(ours), `\ufffd`, "invalid UTF-8 was not exercised")
					require.Contains(t, string(ours), "\\t", "control characters were not exercised")
				}
			}
		})
	}
}

func TestJSONSafeFormatterMIME(t *testing.T) {
	require.Equal(t, "application/json; charset=utf-8", jsonSafeFormatter{}.MIME())
}
