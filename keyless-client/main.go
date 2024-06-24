package main

import (
	"context"
	"keyless-client/internal/handler"
	"keyless-client/internal/slogger"
)

var logger = slogger.Logger

func startProxy(cFunc context.CancelFunc) {
	go func() {
		if err := handler.Proxy(context.Background()); err != nil {
			logger.Error("Proxy error", slogger.ErrorAttr(err))
		}
		cFunc()
	}()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	startProxy(cancel)
	select {
	case <-ctx.Done():
		logger.Info("done")
	}
}
