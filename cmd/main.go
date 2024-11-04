package main

import (
	"C"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	cert "github.com/playables-studio/yandex-games-dev-proxy"
)
import "context"

var (
	server    *http.Server
	host      = ""
	path      = ""
	appID     = ""
	csp       = false
	logReq    = true
	port      = 8080
	tld       = "ru"
	cspData   = ""
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
func StartServer(goHost, goPath, goAppID *C.char, goCsp bool, goPort int, goTld *C.char, goLogReq bool) {
	host = C.GoString(goHost)
	path = C.GoString(goPath)
	appID = C.GoString(goAppID)
	csp = goCsp
	port = goPort
	tld = C.GoString(goTld)
	logReq = goLogReq

	mux := http.NewServeMux()

	if logReq {
		mux.HandleFunc("/", loggingMiddleware(handler))
	} else {
		mux.HandleFunc("/", handler)
	}

	if csp {
		go fetchCSPWithRetry()
	}

	certificate, err := cert.NewCertificateManager().GetOrCreateCertificate()
	if err != nil {
		log.Printf("Failed to get or create certificate: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ClientAuth:         tls.NoClientCert,
		InsecureSkipVerify: true,
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
	if appID != "" {
		url := fmt.Sprintf("https://yandex.%s/games/app/%s/?draft=true&game_url=https://localhost:%d", tld, appID, port)
		log.Printf("You can open your game with %s\n", url)
	}

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

func fetchCSPWithRetry() {
	maxRetries := 3
	retryDelay := time.Second * 2

	for i := 0; i < maxRetries; i++ {
		if err := fetchCSP(); err != nil {
			log.Printf("CSP fetch attempt %d failed: %v", i+1, err)
			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay *= 2 // Exponential backoff
				continue
			}
		}
		break
	}
}

func fetchCSP() error {
	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	appUrl := fmt.Sprintf("https://yandex.%s/games/app/%s?draft=true", tld, appID)
	resp, err := client.Get(appUrl)
	if err != nil {
		return fmt.Errorf("error fetching CSP: %v", err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return fmt.Errorf("error parsing HTML: %v", err)
	}

	gameFrameSrc, exists := doc.Find("#game-frame").Attr("src")
	if !exists {
		return fmt.Errorf("game frame not found")
	}

	gameResp, err := client.Get(gameFrameSrc)
	if err != nil {
		return fmt.Errorf("error fetching game HTML: %v", err)
	}
	defer gameResp.Body.Close()

	gameDoc, err := goquery.NewDocumentFromReader(gameResp.Body)
	if err != nil {
		return fmt.Errorf("error parsing game HTML: %v", err)
	}

	metaContent, exists := gameDoc.Find("meta[http-equiv=Content-Security-Policy]").Attr("content")
	if exists {
		// Modify CSP to work with Unity
		cspData = modifyCSPForUnity(metaContent)
	}

	return nil
}

func modifyCSPForUnity(originalCSP string) string {
	// Split the CSP into directives
	directives := strings.Split(originalCSP, ";")
	modifiedDirectives := make([]string, 0, len(directives))

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		// Modify specific directives that might affect Unity
		if strings.HasPrefix(directive, "default-src") {
			directive = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:"
		} else if strings.HasPrefix(directive, "script-src") {
			directive = "script-src * 'unsafe-inline' 'unsafe-eval'"
		} else if strings.HasPrefix(directive, "connect-src") {
			directive = "connect-src * ws: wss:"
		}

		modifiedDirectives = append(modifiedDirectives, directive)
	}

	return strings.Join(modifiedDirectives, "; ")
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

	if path != "" {
		serveStaticFiles(w, r)
	} else if host != "" {
		proxyHandler(w, r)
	}
}

func serveStaticFiles(w http.ResponseWriter, r *http.Request) {
	fileServer := http.FileServer(http.Dir(path))
	if csp && r.URL.Path == "/" {
		serveWithCSP(w, r, fileServer)
	} else {
		fileServer.ServeHTTP(w, r)
	}
}

func serveWithCSP(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	if cspData != "" {
		w.Header().Set("Content-Security-Policy", cspData)
	}
	handler.ServeHTTP(w, r)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	parsedURL, err := url.Parse(fmt.Sprintf("http://%s", host))
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	if cspData != "" && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
		r.Header.Del("Accept-Encoding")
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if cspData != "" && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
			appendCSPMeta(resp)
		}
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, time.Now().Format(time.RFC3339), r.URL.Path)
		next(w, r)
	}
}

func appendCSPMeta(resp *http.Response) {
	if resp.Body == nil {
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(bodyBytes)))
	if err != nil {
		log.Printf("Error parsing HTML: %v", err)
		return
	}

	head := doc.Find("head")
	if head != nil {
		metaTag := fmt.Sprintf(`<meta http-equiv="Content-Security-Policy" content="%s">`, cspData)
		head.AppendHtml(metaTag)
	}

	newBody, _ := doc.Html()
	resp.Body = io.NopCloser(strings.NewReader(newBody))
	resp.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
}

func main() {
}
