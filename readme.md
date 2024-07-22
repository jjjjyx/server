

# server

使用 github.com/refraction-networking/utls 创建的 tls 的监听器时，http服务无法正确握手，针对握手的链接判断，改为判断对象的接口类型来确定。

```

func (c *conn) serve(ctx context.Context) {
    if tlsConn, ok := c.rwc.(*tls.Conn); ok {
        ...
    }
}

//改为：
type HttpsConn interface {
    http2connectionStater
    
    RemoteAddr() net.Addr
    
    HandshakeContext(ctx context.Context) error
}
func (c *conn) serve(ctx context.Context) {
    if tlsConn, ok := c.rwc.(HttpsConn); ok {
        ...
    }
}
```
