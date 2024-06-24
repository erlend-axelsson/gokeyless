package main

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"hash"
	"keyless-signer/internal/handler"
	"keyless-signer/internal/slogger"
	"log"
	"net/http"
	"sync"
)

var logger = slogger.Logger

func init() {
	crypto.RegisterHash(crypto.MD5SHA1, NewMD5Sha1)
}

type Actor struct {
	wg    sync.WaitGroup
	tasks []func()
}

func NewActor() *Actor {
	return &Actor{
		tasks: make([]func(), 0),
		wg:    sync.WaitGroup{},
	}
}

func (actor *Actor) AddTask(task func()) {
	actor.tasks = append(actor.tasks, task)
	actor.wg.Add(1)
}

func (actor *Actor) Run() {
	for _, task := range actor.tasks {
		go func() {
			logger.Debug("starting task")
			task()
			actor.wg.Done()
			logger.Debug("finished task")
		}()
	}
	actor.wg.Wait()
	logger.Debug("finished all tasks")
}

func addServer(actor *Actor, server *http.Server) {
	logger.Debug("Adding server " + server.Addr)
	actor.AddTask(func() {
		logger.Info("starting server " + server.Addr)
		if err := server.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
			logger.Debug(err.Error())
		}
		logger.Info("server closed " + server.Addr)
	})
}

type md5Sha1 struct {
	buffer bytes.Buffer
}

func NewMD5Sha1() hash.Hash {
	return &md5Sha1{
		buffer: bytes.Buffer{},
	}
}

func (h *md5Sha1) Sum(b []byte) []byte {
	out := make([]byte, len(b), len(b)+md5.Size+sha1.Size)
	copy(out, b)
	h.buffer.Write(b)
	md5Sum := md5.Sum(h.buffer.Bytes())
	sha1Sum := sha1.Sum(h.buffer.Bytes())
	out = append(out, md5Sum[:]...)
	out = append(out, sha1Sum[:]...)
	return out
}

func (h *md5Sha1) Write(b []byte) (n int, err error) {
	return h.buffer.Write(b)
}

func (h *md5Sha1) Size() int {
	return md5.Size + sha1.Size
}

func (h *md5Sha1) Reset() {
	h.buffer.Reset()
}

func (h *md5Sha1) BlockSize() int {
	return 64
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, World!"))
}

func signingServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", helloHandler)
	mux.HandleFunc("POST /sign", handler.SignHandler)
	mux.HandleFunc("POST /cert", handler.CertHandler)
	server := &http.Server{
		Addr:    ":9999",
		Handler: mux,
	}
	return server
}

func main() {
	actor := NewActor()
	addServer(actor, signingServer())
	actor.Run()
}
