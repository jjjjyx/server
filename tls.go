package server

import (
	"context"
	"net"
)

type HttpsConn interface {
	net.Conn

	http2connectionStater
	HandshakeContext(ctx context.Context) error
}
