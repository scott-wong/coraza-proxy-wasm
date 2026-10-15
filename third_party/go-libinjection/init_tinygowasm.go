// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo.wasm

package libinjection

/*
#cgo LDFLAGS: -Lwasm -linjection
*/
import "C"
