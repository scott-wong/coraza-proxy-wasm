// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo

package auditlog

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins"
)

// RegisterProxyWasmJSONFormatter overrides the built-in "json" audit-log
// formatter with a version that is safe to run under TinyGo.
//
// Registration happens in the plugin's init(), which runs after coraza's own
// package init() has registered the original "json" formatter, so this
// replaces it. The registry (coraza's auditlog.RegisterFormatter) is a plain
// map assignment and does not reject duplicates.
//
// It only replaces the formatter: the output is byte-for-byte identical to
// coraza's (see json_safe.go and json_safe_test.go), so audit logs keep their
// schema regardless of whether a user sets SecAuditLogFormat JSON.
func RegisterProxyWasmJSONFormatter() {
	plugins.RegisterAuditLogFormatter("json", jsonSafeFormatter{})
}
