package handler

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	model "go-security/api/model"
	"net/http"
	"strings"
	"time"
)

// @Tag security
// @Title Get HTTP Security Headers
// @Description Get HTTP Security Headers for multiple URLs.
// @Param urls query string true "Target URLs to check security headers (comma-separated)"
// @Success 200 {object} map[string]model.SecurityHeaders "Map of URLs to their security headers"
// @Failure 400 {string} string "URLs parameter is required"
// @Failure 500 {string} string "Unable to fetch one or more URLs"
// @Router /security [get]
func GetSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("urls")
	if urlParam == "" {
		http.Error(w, "URLs parameter is required", http.StatusBadRequest)
		return
	}

	urls := strings.Split(urlParam, ",")
	results := make(map[string]model.SecurityHeaders)

	for _, url := range urls {
		resp, err := http.Get(strings.TrimSpace(url))
		if err != nil {
			http.Error(w, fmt.Sprintf("Unable to fetch URL: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		results[url] = model.SecurityHeaders{
			StrictTransportPolicy: resp.Header.Get("Strict-Transport-Security"),
			XFrameOptions:         resp.Header.Get("X-Frame-Options"),
			XContentTypeOptions:   resp.Header.Get("X-Content-Type-Options"),
			XXSSProtection:        resp.Header.Get("X-XSS-Protection"),
			ContentSecurityPolicy: resp.Header.Get("Content-Security-Policy"),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// @Tag security
// @Title Get SSL/TLS Configuration
// @Description Get SSL/TLS configuration details for a given URL.
// @Param urls query string true "Target URLs to check SSL/TLS configuration (comma-separated)"
// @Success 200 {object} map[string]model.SSLConfig "SSL/TLS configuration details"
// @Failure 400 {string} string "URL parameter is required"
// @Failure 500 {string} string "Unable to fetch SSL/TLS details"
// @Router /ssl [get]
func GetSSLConfig(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("urls")
	if urlParam == "" {
		http.Error(w, "URL parameter is required", http.StatusBadRequest)
		return
	}

	urls := strings.Split(urlParam, ",")
	results := make(map[string]model.SSLConfig)

	tlsVersions := map[string]uint16{
		"TLS 1.0": tls.VersionTLS10,
		"TLS 1.1": tls.VersionTLS11,
		"TLS 1.2": tls.VersionTLS12,
		"TLS 1.3": tls.VersionTLS13,
	}

	cipherSuites := map[string]uint16{
		"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		// Add other cipher suites as needed
	}

	for _, url := range urls {
		supportedProtocols := []string{}
		supportedCipherSuites := []string{}
		var sslConfig model.SSLConfig

		for versionName, versionConst := range tlsVersions {
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						MinVersion:         versionConst,
						MaxVersion:         versionConst,
						InsecureSkipVerify: true,
					},
				},
			}

			resp, err := client.Get(url)
			if err == nil {
				supportedProtocols = append(supportedProtocols, versionName)
				connState := resp.TLS
				resp.Body.Close()

				if sslConfig.Subject == "" && connState != nil && len(connState.PeerCertificates) > 0 {
					cert := connState.PeerCertificates[0]
					sslConfig = model.SSLConfig{
						Subject: cert.Subject.CommonName,
						Issuer:  cert.Issuer.Organization[0],
						Expiry:  cert.NotAfter,
					}
				}
			}
		}

		for cipherName, cipherConst := range cipherSuites {
			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						CipherSuites:       []uint16{cipherConst},
						InsecureSkipVerify: true,
					},
				},
			}

			resp, err := client.Get(url)
			if err == nil {
				supportedCipherSuites = append(supportedCipherSuites, cipherName)
				resp.Body.Close()
			}
		}

		sslConfig.SupportedProtocols = supportedProtocols
		sslConfig.SupportedCipherSuites = supportedCipherSuites
		results[url] = sslConfig
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
