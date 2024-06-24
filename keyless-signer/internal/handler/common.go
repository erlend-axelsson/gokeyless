package handler

import (
	"keyless-signer/internal/slogger"
	"keyless-signer/internal/util"
	"net/http"
)

var logger = slogger.Logger

func BodyCloser(w http.ResponseWriter, r *http.Request) {
	err := r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, wErr := w.Write([]byte(err.Error()))
		if wErr != nil {
			return
		}
	}
}

func setContentType(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
}

func setContentJson(w http.ResponseWriter) {
	setContentType(w, "application/json")
}

func respondWithError(w http.ResponseWriter, err *util.JsonErr) {
	w.WriteHeader(err.StatusCode)
	setContentType(w, "application/problem+json; charset=utf-8")
	if _, wErr := w.Write([]byte(err.Error())); wErr != nil {
		logger.Error(wErr.Error())
	}
}
