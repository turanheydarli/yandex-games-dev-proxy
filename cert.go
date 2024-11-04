package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	certValidityDays = 365
	rsaKeySize       = 2048
	orgName          = "Yandex SDK Development Certificate"
)

type CertificateManager struct {
	certPath string
	keyPath  string
}

func NewCertificateManager() *CertificateManager {
	// Save certificates in a more permanent directory, such as the user's home directory.
	certDir := filepath.Join(os.Getenv("HOME"), ".yandex_sdk")
	os.MkdirAll(certDir, 0755) // Ensure the directory exists.

	return &CertificateManager{
		certPath: filepath.Join(certDir, "yandex_sdk_cert.pem"),
		keyPath:  filepath.Join(certDir, "yandex_sdk_key.pem"),
	}
}

func (cm *CertificateManager) GetOrCreateCertificate() (tls.Certificate, error) {
	// Check if certificate exists and is valid
	if cm.isValidCertificate() {
		return tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	}

	// Generate new certificate
	certPEM, keyPEM, err := cm.generateCertificate()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Save certificate and key
	if err := cm.saveCertificateAndKey(certPEM, keyPEM); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to save certificate: %v", err)
	}

	// Add the certificate to the system's trust store
	if err := cm.addCertToTrustStore(); err != nil {
		log.Printf("Warning: Failed to add certificate to the system's trust store: %v", err)
	} else {
		log.Printf("Certificate successfully added to the system's trust store.")
	}

	// Load and return the new certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load generated certificate: %v", err)
	}

	return cert, nil
}

func (cm *CertificateManager) isValidCertificate() bool {
	if !fileExists(cm.certPath) || !fileExists(cm.keyPath) {
		return false
	}

	// Check if the certificate is valid and has required SANs
	certPEM, err := os.ReadFile(cm.certPath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter) && cm.validateSANs(cert)
}

func (cm *CertificateManager) validateSANs(cert *x509.Certificate) bool {
	hasLocalhost := false
	hasLoopback := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			hasLocalhost = true
			break
		}
	}
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.ParseIP("::1")) {
			hasLoopback = true
		}
	}
	return hasLocalhost && hasLoopback
}

func (cm *CertificateManager) generateCertificate() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{orgName},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(certValidityDays * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

func (cm *CertificateManager) saveCertificateAndKey(certPEM, keyPEM []byte) error {
	// Save the certificate and key to permanent files
	if err := os.WriteFile(cm.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}
	if err := os.WriteFile(cm.keyPath, keyPEM, 0600); err != nil {
		os.Remove(cm.certPath) // Clean up certificate if key write fails
		return fmt.Errorf("failed to save private key: %v", err)
	}
	return nil
}

// addCertToTrustStore adds the generated certificate to the system's trust store on macOS and Windows
func (cm *CertificateManager) addCertToTrustStore() error {
	switch runtime.GOOS {
	case "darwin":
		return addCertToMacOSTrustStore(cm.certPath)
	case "windows":
		return addCertToWindowsTrustStore(cm.certPath)
	default:
		return fmt.Errorf("unsupported operating system")
	}
}

func addCertToMacOSTrustStore(certPath string) error {
	//security add-trusted-cert -p basic -p ssl -k <<login-keychain>> <<certificate>>
	///Users/turanheydarli/Library/Keychains/login.keychain-db
	cmd := exec.Command("security", "add-trusted-cert", "-p", "basic", "-p", "ssl", "-k", "/Users/turanheydarli/Library/Keychains/login.keychain-db", certPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add certificate to macOS trust store: %v", err)
	}
	return nil
}

func addCertToWindowsTrustStore(certPath string) error {
	cmd := exec.Command("certutil", "-addstore", "Root", certPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add certificate to Windows trust store: %v", err)
	}
	return nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
