package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var (
	host    = flag.String("host", "", "Host where your game is available")
	path    = flag.String("path", "", "The folder where your game is located")
	appID   = flag.String("app-id", "", "ID of your game")
	csp     = flag.Bool("csp", false, "Include CSP header")
	port    = flag.Int("port", 8080, "Port to use")
	logReq  = flag.Bool("log", true, "Enable request logger")
	tld     = flag.String("tld", "ru", "TLD of yandex domain")
	cspData = ""
)

func main() {
	flag.Parse()

	if *host == "" && *path == "" {
		log.Fatal("Error: one of path or host options required")
	}

	mux := http.NewServeMux()

	if *logReq {
		mux.HandleFunc("/", loggingMiddleware(handler))
	} else {
		mux.HandleFunc("/", handler)
	}

	if *csp {
		go fetchCSP() // Fetch CSP in the background
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Server is running on https://localhost:%d/\n", *port)
	if *appID != "" {
		url := fmt.Sprintf("https://yandex.%s/games/app/%s/?draft=true&game_url=https://localhost:%d", *tld, *appID, *port)
		log.Printf("You can open your game with %s\n", url)
	}

	err := server.ListenAndServeTLS("./server.crt", "./server.key")
	if err != nil {
		log.Fatal(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	if *path != "" {
		serveStaticFiles(w, r)
	} else if *host != "" {
		proxyHandler(w, r)
	}
}

func serveStaticFiles(w http.ResponseWriter, r *http.Request) {
	fileServer := http.FileServer(http.Dir(*path))
	if *csp && r.URL.Path == "/" {
		serveWithCSP(w, r, fileServer)
	} else {
		fileServer.ServeHTTP(w, r)
	}
}

func serveWithCSP(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	// Write CSP header before serving
	if cspData != "" {
		w.Header().Set("Content-Security-Policy", cspData)
	}
	handler.ServeHTTP(w, r)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	parsedURL, err := url.Parse(fmt.Sprintf("http://%s", *host))
	if err != nil {
		log.Fatalf("Error parsing URL: %v", err)
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

func fetchCSP() {
	appUrl := fmt.Sprintf("https://yandex.%s/games/app/%s?draft=true", *tld, *appID)
	resp, err := http.Get(appUrl)
	if err != nil {
		log.Printf("Error fetching CSP: %v", err)
		return
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("Error parsing HTML: %v", err)
		return
	}

	gameFrameSrc, exists := doc.Find("#game-frame").Attr("src")
	if !exists {
		return
	}

	gameResp, err := http.Get(gameFrameSrc)
	if err != nil {
		log.Printf("Error fetching game HTML: %v", err)
		return
	}
	defer gameResp.Body.Close()

	gameDoc, err := goquery.NewDocumentFromReader(gameResp.Body)
	if err != nil {
		log.Printf("Error parsing game HTML: %v", err)
		return
	}

	metaContent, exists := gameDoc.Find("meta[http-equiv=Content-Security-Policy]").Attr("content")
	if exists {
		cspData = metaContent
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

	newBody, err := doc.Html()
	resp.Body = io.NopCloser(strings.NewReader(newBody))
	resp.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
}
