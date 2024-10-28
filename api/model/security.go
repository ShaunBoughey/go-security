package security

import "time"

type SecurityHeaders struct {
	StrictTransportPolicy string `json:"strictTransportPolicy,omitempty"`
	XFrameOptions         string `json:"xFrameOptions,omitempty"`
	XContentTypeOptions   string `json:"xContentTypeOptions,omitempty"`
	XXSSProtection        string `json:"xXSSProtection,omitempty"`
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`
}

type SSLConfig struct {
	Subject               string    `json:"subject"`
	Issuer                string    `json:"issuer"`
	Expiry                time.Time `json:"expiry"`
	SupportedProtocols    []string  `json:"supportedProtocols"`
	SupportedCipherSuites []string  `json:"cipherSuite"`
}
