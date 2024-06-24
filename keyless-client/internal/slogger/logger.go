package slogger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
)

var Logger = logger()

func logger() *slog.Logger {
	handler := slog.NewJSONHandler(&prettyWriter{
		buf: bytes.Buffer{},
	}, &slog.HandlerOptions{
		AddSource: true,
	})
	return slog.New(handler)
}

func ErrorAttr(err error) slog.Attr {
	return slog.String("error", err.Error())
}

type prettyWriter struct {
	buf bytes.Buffer
}

func (w *prettyWriter) Write(p []byte) (int, error) {
	if err := json.Indent(&w.buf, p, "", "  "); err != nil {
		return 0, err
	}
	n, err := w.buf.WriteTo(os.Stdout)
	w.buf.Reset()
	return int(n), err
}
