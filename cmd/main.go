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
)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
)

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Your SDK Name"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

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

const (
	certPEM = `-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIUEhdlNwxCdAB4A5sc+huKCeSksvYwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yNDA0MDIxNjMzMzJaGA8yMTI0
MDMwOTE2MzMzMlowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKg8TOLFjeDe/Wy5oXJjaQpAGxCKnLT+io8/EUgF
KlRkamD2dJVZ+1OT8cDI6oju82ZY3DfGQMwg+Cgh/PLMlPXOyfsBFGiwBmAYwIM8
Ixa1ZCgDzPqkFhuvpAjTUoOMkehEEIpvCdrJ78ahD7cOlh+iOe/c8TpuOs+T68rF
3KAqjnicghfjnVyTg99ySZFIFvwbOlfPgbe2yXAqfnwAxy6wwDgP+3Jk7yYuR9Ip
YaXFzVyXnRxaRBFdsYuv0CgacpBbghNdYn6sZmj4phyVubwXkq64oyLHe/lMegZl
qzOumm9qfRQ9G0vGi8xzelKxfPj+Vag/uR4MstlglsRk68sCAwEAAaMhMB8wHQYD
VR0OBBYEFHtFH3JDmoGMV09qBHorWWkp9sckMA0GCSqGSIb3DQEBCwUAA4IBAQAg
vjNymnac6QuYv7lRbCWyzOfwskyMSuYvZp7Otc0xw28wLLcY55/iT2kfxo3zkCCF
piv0kzd7kmN3ctJ0gT4+J+H68jEjOjDQuPu6lzvLnZLessIMdHX7A0kJxDicJawr
sj43w3VKvcvackgK1L+2DD0YNPVzlNCeRVy2QukwtH5mI5OeVcQiV6/2oZLVnKFG
nISCKinpJX7LgBsnAT/eB6d3S3wGc9iWflOWGWB7aqNhoZNxWzsuGgVC/G3Tbayo
c0Yerzk2MCZjMAcbb8TMXGU9vfqjrxn65/X4On+14UIOk97uBGBNfc0JZL945T/S
DI71niYu4L3UMuTsam8F
-----END CERTIFICATE-----`

	keyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCoPEzixY3g3v1s
uaFyY2kKQBsQipy0/oqPPxFIBSpUZGpg9nSVWftTk/HAyOqI7vNmWNw3xkDMIPgo
IfzyzJT1zsn7ARRosAZgGMCDPCMWtWQoA8z6pBYbr6QI01KDjJHoRBCKbwnaye/G
oQ+3DpYfojnv3PE6bjrPk+vKxdygKo54nIIX451ck4PfckmRSBb8GzpXz4G3tslw
Kn58AMcusMA4D/tyZO8mLkfSKWGlxc1cl50cWkQRXbGLr9AoGnKQW4ITXWJ+rGZo
+KYclbm8F5KuuKMix3v5THoGZaszrppvan0UPRtLxovMc3pSsXz4/lWoP7keDLLZ
YJbEZOvLAgMBAAECggEAGyq5o7kRIyn/NIp5ZrZk5PHbLP2lNpkQGPevO7kRz9Tz
VLsXsnJ4YlO2q1IGhZxIk9NvpFYQaqY8TIbIiRC+UT9WYIEZIZqjPOtiUw7n/6fF
B60tcaADre7cB0zQu0t82Ev9e81Ygwsu/B1QI1hop60TvAcqsSvRtWmGnxT6fqZ9
H4MJDzSEyoUyUdPaIvdXPYMO66wGqvfTVagZ0zl0cJf/yH+fwGKinq7CDpDWFo6T
7pjbfVjCiQORblBul6zNwMc7tp2KgBk+YpHk3rKcV426tKYAddurhL/AGKV4uSU7
ZqnaBYWjPqd8qli6QMVNqOwDrYHtDIO7Tb0k0HZd2QKBgQDp8amKJsRMqHoXqzUB
HW2EJh/ARrVVsOEAYFKXVa2JTJ0Rojw2ITXu+zSLW0ieI6QRvZmesLB3fxzD8wpo
TCMSot45jyqeDIBr/HlJpEJ+F3wRB01j5M67NHRUH8FRu4C1Iq7iYx6YTHlER8YQ
VO68OZ8jkzSAQMUrKmviXBOpvQKBgQC4GLyf4qrE6Pp2s6qxrqv0eB5x2Uw8jGYe
RUrK42KooZnBruDBLjIlK6TJwsm4IS/4BMNz21ddA4HqSP4cmjWB/ziGLgEN/dNJ
dMmvhfTeK3zaDu8UF0oFe1lyKV4kVXfUnIElMXpqBsJA0l2GZvLOuUivRpHfeP57
PQ9Mz/dQJwKBgQDkLr2yLZvcNZxYx7p8auquMc1Yat9mRI9CIbGNQJlySRMO5xIZ
rg0AG2+l2ZScAqF+WFOlcCu/cnFpQv7Mui6fd9KPi/AClqkQKwNWa+wbNubhaSD4
JW3rNP+eKhcSlHO2uaygzhNCc5z4l5U9ysnNN9rcBTH5QrPOJaNy92KKdQKBgQCw
eQ3/2kHG5mqJ9SqwjvdJLwhILHw3IoMVi2jp2lUNv3Nrxd6vcEAjf5XEztOdjTq1
bqOJ4P37LMyRsIzfEDgwuF4PyfO63NF4fdqERk331wok4eHuiXCslpSkqeETxVZM
WgY2iBqHnpkBmGaM2wzwe46gbm6RISQZMOwEvuqdSwKBgQCcAvA7QsSBN7CpIx+j
EEGcIbZ8DFfsZ91pwyxXfOYkpD1eBpwY3PFeGVkvdSB4w+1RmNDB9GV6xRQsFV5j
Kyt6MeZNerWnPu4Che55N+xtiGPNq/pR5KfcpYkbjpSCoJ3etkMZWZ/zx+l4AyaO
GTxuQXvdfeOlaDFjsDK6UtLBzg==
-----END PRIVATE KEY-----`
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
		go fetchCSP()
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Printf("Failed to generate self-signed certificate: %v", err)
		return
	}

	server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
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
		err := server.Close()
		if err != nil {
			log.Printf("Error stopping server: %v", err)
		} else {
			log.Println("Server stopped successfully.")
		}
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
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

func fetchCSP() {
	appUrl := fmt.Sprintf("https://yandex.%s/games/app/%s?draft=true", tld, appID)
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

	newBody, _ := doc.Html()
	resp.Body = io.NopCloser(strings.NewReader(newBody))
	resp.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
}

func main() {
}
