package main

import (
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("rootHandler")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("" +
		"<html>" +
		"	<head>" +
		"		<title>Go proxy target</title>" +
		"	</head>" +
		"	<body>" +
		"		<h1>Go proxy target</h1>" +
		"	</body>" +
		"</html>"))
}

func getServer() http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	return http.Server{
		Addr:    ":8081",
		Handler: mux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func main() {
	srv := getServer()
	log.Fatalln(srv.ListenAndServe())
}
