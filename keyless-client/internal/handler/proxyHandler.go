package handler

import (
	"context"
	"crypto/tls"
	"io"
	"keyless-client/internal/certs"
	"keyless-client/internal/env"
	"keyless-client/internal/slogger"
	"log/slog"
	"net"
	"net/url"
	"sync"
)

var logger = slogger.Logger

func Proxy(ctx context.Context) error {
	logger.Debug("Proxy start")
	local, err := tlsListener(env.LAddr)
	if err != nil {
		logger.Error("create tls listener error", slogger.ErrorAttr(err))
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return local.Close()
		default:
			listen(local, env.RAddr)
		}
	}
}

func listen(listener net.Listener, target string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("accept error", slogger.ErrorAttr(err))
			return
		}
		logger.Debug(
			"accepted connection",
			slog.String("network", listener.Addr().Network()),
			slog.String("addr", listener.Addr().String()),
			slog.String("target", target),
		)
		go handleConnection(conn, target)
	}
}

func handleConnection(conn net.Conn, target string) {
	logger.Debug("dial target", slog.String("target", target))
	rConn, err := tcpDial(target)

	defer closeConn(conn)
	defer closeConn(rConn)

	if err != nil {
		logger.Error("failed to dial target",
			slog.String("target", target),
			slog.Any("dialErr", err),
			slog.Any("closeErr", conn.Close()),
		)
		return
	}
	logger.Debug("proxying request to target")
	wg := sync.WaitGroup{}
	wg.Add(2)
	go transfer(&wg, conn, rConn)
	go transfer(&wg, rConn, conn)
	wg.Wait()
	logger.Info("request completed")
}

func transfer(wg *sync.WaitGroup, from, to net.Conn) {
	defer wg.Done()
	if _, err := io.Copy(to, from); err != nil {
		logger.Warn("transfer error", slogger.ErrorAttr(err))
	}
}

func tlsListener(uri string) (net.Listener, error) {
	addr, err := resolveAddr(uri)
	if err != nil {
		logger.Error("resolve address error", slogger.ErrorAttr(err))
		return nil, err
	}
	return tls.Listen("tcp", addr.String(), &tls.Config{
		GetCertificate: certs.GetSeverCertificate,
	})
}
func tcpDial(uri string) (net.Conn, error) {
	addr, err := resolveAddr(uri)
	if err != nil {
		logger.Error("dial error", slogger.ErrorAttr(err))
		return nil, err
	}
	return net.Dial(addr.Network(), addr.String())
}

func getHost(addr string) (string, error) {
	uri, err := url.Parse(addr)
	if err != nil {
		logger.Error("parse host error", slogger.ErrorAttr(err))
		return "", err
	}
	return uri.Host, nil
}

func resolveAddr(addr string) (*net.TCPAddr, error) {
	host, err := getHost(addr)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", host)
}

func closeConn(conn net.Conn) {
	if err := conn.Close(); err != nil {
		logger.Error("close conn error", slogger.ErrorAttr(err))
	}
}
