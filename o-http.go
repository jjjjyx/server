package server

import (
	"golang.org/x/net/http/httpguts"
	"time"
)

// omitBundledHTTP2 is set by omithttp2.go when the nethttpomithttp2
// build tag is set. That means h2_bundle.go isn't compiled in and we
// shouldn't try to use it.
var omitBundledHTTP2 bool

// The algorithm uses at most sniffLen bytes to make its decision.
const sniffLen = 512

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type incomparable [0]func()

// maxInt64 is the effective "infinite" value for the Server and
// Transport's byte-limiting readers.
const maxInt64 = 1<<63 - 1

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(1, 0)

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "net/http context value " + k.name }

// OriginHeaderNamesExtraKey 在request 中保存原始 读取到的 header 名称和顺序
const OriginHeaderNamesExtraKey = "x-server-request-header-origin"
