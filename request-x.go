package server

import (
	"context"
	"net/http"
)

// RequestX 扩展http.Request
// 附加一些当前请求的指纹信息
type RequestX struct {
	*http.Request

	ClientHello []byte

	HeaderOrder []string

	Headers map[string][]string

	Frames FramesData
}

type FramesData struct {
	Setting               []http2Setting
	Increment             uint32
	HeaderNameOrder       []string
	PseudoHeaderNameOrder []string
	HeaderPriority        http2PriorityParam
	HeaderFlag            http2Flags // 没什么用
	Priority              []http2PriorityFrame
}

func (d FramesData) Zero() bool {
	return d.Increment == 0
}

// WithContext returns a shallow copy of r with its context changed
// to ctx. The provided ctx must be non-nil.
//
// For outgoing client request, the context controls the entire
// lifetime of a request and its response: obtaining a connection,
// sending the request, and reading the response headers and body.
//
// To create a new request with a context, use NewRequestWithContext.
// To make a deep copy of a request with a new context, use Request.Clone.
func (r *RequestX) WithContext(ctx context.Context) *RequestX {
	if ctx == nil {
		panic("nil context")
	}

	r.Request = r.Request.WithContext(ctx)
	//r2 := new(http.Request)
	//*r2 = *r
	//r2.ctx = ctx
	return r
}

type HandlerX interface {
	ServeHTTP(http.ResponseWriter, *RequestX)
}

type ServeMux struct {
}

func (s ServeMux) ServeHTTP(_ http.ResponseWriter, _ *RequestX) {

}

var DefaultServeMux = &defaultServeMux

var defaultServeMux ServeMux
