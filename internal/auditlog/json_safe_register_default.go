// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package auditlog

// RegisterProxyWasmJSONFormatter is a no-op outside TinyGo builds: the host
// formatter works fine (its encoding/json has a complete reflect package), and
// keeping coraza's own formatter there is what lets json_safe_test.go compare
// the two implementations byte-for-byte.
func RegisterProxyWasmJSONFormatter() {}
