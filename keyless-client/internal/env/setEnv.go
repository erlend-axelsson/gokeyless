package env

import (
	"flag"
	"keyless-client/internal/slogger"
	"log/slog"
	"os"
)

// initialized with fallback values

var SigUrl string = "http://localhost:9999"
var LAddr string = "http://localhost:8080"
var RAddr string = "http://localhost:8081"

const (
	SigUrlKey = "sigUrl"
	lAddrKey  = "lAddr"
	rAddrKey  = "rAddr"
)

var logger = slogger.Logger

func init() {
	kvValue := flag.String(SigUrlKey, "", "Signer Url")
	lAddrValue := flag.String(lAddrKey, "", "local host")
	rAddrValue := flag.String(rAddrKey, "", "remote host")
	flag.Parse()

	if isPresent(kvValue) {
		SigUrl = *kvValue
	} else if envVal, ok := os.LookupEnv(SigUrlKey); ok {
		SigUrl = envVal
	} else {
		logger.Warn("SigUrl is missing, using default", slog.String("value", SigUrl))
	}

	if isPresent(lAddrValue) {
		LAddr = *lAddrValue
	} else if envVal, ok := os.LookupEnv(lAddrKey); ok {
		LAddr = envVal
	} else {
		logger.Warn("lAddr is missing, using default", slog.String("value", LAddr))
	}

	if isPresent(rAddrValue) {
		RAddr = *rAddrValue
	} else if envVal, ok := os.LookupEnv(rAddrKey); ok {
		RAddr = envVal
	} else {
		logger.Warn("rAddr is missing, using default", slog.String("value", RAddr))
	}
}

func isPresent(val *string) bool {
	return val != nil && *val != ""
}
