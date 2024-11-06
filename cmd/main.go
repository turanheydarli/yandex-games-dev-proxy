package main

import (
	"C"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cert "github.com/playables-studio/yandex-games-dev-proxy"
)

var (
	server    *http.Server
	path      = ""
	csp       = false
	logReq    = true
	port      = 8080
	logBuffer strings.Builder
	logMutex  sync.Mutex
)

func init() {
	log.SetOutput(&safeLogWriter{})
}

type safeLogWriter struct{}

func (w *safeLogWriter) Write(p []byte) (n int, err error) {
	logMutex.Lock()
	defer logMutex.Unlock()
	return logBuffer.Write(p)
}

//export GetLogs
func GetLogs() *C.char {
	logMutex.Lock()
	defer logMutex.Unlock()
	logs := logBuffer.String()
	logBuffer.Reset()
	return C.CString(logs)
}

//export StartServer
func StartServer(goPath *C.char, goCsp bool, goPort int, goLogReq bool) {
	path = C.GoString(goPath)
	csp = goCsp
	port = goPort
	logReq = goLogReq

	mux := http.NewServeMux()

	if logReq {
		mux.HandleFunc("/", loggingMiddleware(handler))
	} else {
		mux.HandleFunc("/", handler)
	}

	// Use the CertificateManager from the cert package
	certManager := cert.NewCertificateManager()
	certificate, err := certManager.GetOrCreateCertificate()
	if err != nil {
		log.Printf("Failed to get or create certificate: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	server = &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Server is running on https://localhost:%d/\n", port)

	err = server.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		log.Printf("Server error: %v", err)
	}
}

//export StopServer
func StopServer() {
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Printf("Error shutting down server: %v", err)
		} else {
			log.Printf("Server stopped successfully")
		}
	} else {
		log.Printf("Server is not running")
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers for Unity
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	serveStaticFiles(w, r)
}

func serveStaticFiles(w http.ResponseWriter, r *http.Request) {
	if csp && r.URL.Path == "/" {
		serveWithCSP(w, r, compressedFileHandler())
	} else {
		compressedFileHandler().ServeHTTP(w, r)
	}
}

func serveWithCSP(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:")
	handler.ServeHTTP(w, r)
}

func compressedFileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the Accept-Encoding header
		acceptEncoding := r.Header.Get("Accept-Encoding")
		log.Printf("Request for %s with Accept-Encoding: %s", r.URL.Path, acceptEncoding)

		filePath := filepath.Join(path, filepath.Clean(r.URL.Path))
		info, err := os.Stat(filePath)
		if err != nil {
			// File does not exist
			http.NotFound(w, r)
			return
		}

		// If it's a directory, serve index.html
		if info.IsDir() {
			filePath = filepath.Join(filePath, "index.html")
			info, err = os.Stat(filePath)
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}

		var encoding string
		var compressedFilePath string
		var compressedFileInfo os.FileInfo

		if strings.Contains(acceptEncoding, "br") {
			// Check for Brotli compressed file
			compressedFilePath = filePath + ".br"
			if fi, err := os.Stat(compressedFilePath); err == nil {
				encoding = "br"
				compressedFileInfo = fi
			}
		}

		if encoding == "" && strings.Contains(acceptEncoding, "gzip") {
			// Check for Gzip compressed file
			compressedFilePath = filePath + ".gz"
			if fi, err := os.Stat(compressedFilePath); err == nil {
				encoding = "gzip"
				compressedFileInfo = fi
			}
		}

		if encoding != "" {
			log.Printf("Serving compressed file: %s with encoding: %s", compressedFilePath, encoding)

			// Serve compressed file
			f, err := os.Open(compressedFilePath)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer f.Close()

			ext := filepath.Ext(filePath)
			contentType := mime.TypeByExtension(ext)
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
			}

			w.Header().Set("Content-Encoding", encoding)
			w.Header().Set("Vary", "Accept-Encoding")
			http.ServeContent(w, r, filePath, compressedFileInfo.ModTime(), f)
		} else {
			log.Printf("Serving uncompressed file: %s", filePath)
			// Serve uncompressed file
			http.ServeFile(w, r, filePath)
		}
	})
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, time.Now().Format(time.RFC3339), r.URL.Path)
		next(w, r)
	}
}

func main() {
}
