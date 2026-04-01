package service

import (
	"testing"

	"github.com/wneessen/go-mail"
)

func TestResolveSMTPTransport(t *testing.T) {
	tests := []struct {
		name           string
		configuredPort int
		expectedPort   int
		expectedUseSSL bool
		expectedPolicy mail.TLSPolicy
	}{
		{
			name:           "default port uses 587 with mandatory tls",
			configuredPort: 0,
			expectedPort:   587,
			expectedUseSSL: false,
			expectedPolicy: mail.TLSMandatory,
		},
		{
			name:           "port 587 uses starttls mandatory",
			configuredPort: 587,
			expectedPort:   587,
			expectedUseSSL: false,
			expectedPolicy: mail.TLSMandatory,
		},
		{
			name:           "port 25 keeps configured port and opportunistic tls",
			configuredPort: 25,
			expectedPort:   25,
			expectedUseSSL: false,
			expectedPolicy: mail.TLSOpportunistic,
		},
		{
			name:           "port 465 enables implicit ssl",
			configuredPort: 465,
			expectedPort:   465,
			expectedUseSSL: true,
			expectedPolicy: mail.NoTLS,
		},
		{
			name:           "custom port uses mandatory tls",
			configuredPort: 2525,
			expectedPort:   2525,
			expectedUseSSL: false,
			expectedPolicy: mail.TLSMandatory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, useSSL, policy := resolveSMTPTransport(tt.configuredPort)
			if port != tt.expectedPort {
				t.Fatalf("expected port %d, got %d", tt.expectedPort, port)
			}
			if useSSL != tt.expectedUseSSL {
				t.Fatalf("expected useSSL %v, got %v", tt.expectedUseSSL, useSSL)
			}
			if policy != tt.expectedPolicy {
				t.Fatalf("expected policy %v, got %v", tt.expectedPolicy, policy)
			}
		})
	}
}
