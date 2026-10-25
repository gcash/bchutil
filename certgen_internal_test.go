// Copyright (c) 2026 the bchd developers.

package bchutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"
)

// TestNewTLSCertPairWithoutInterfaceAddrs ensures a certificate is still
// generated, for the loopback addresses and the extra hosts, when the system
// does not allow reading the addresses of the network interfaces, as Android
// does for apps targeting API 30 or newer.
func TestNewTLSCertPairWithoutInterfaceAddrs(t *testing.T) {
	listInterfaceAddrs = func() ([]net.Addr, error) {
		return nil, errors.New("route ip+net: netlinkrib: permission denied")
	}
	defer func() { listInterfaceAddrs = interfaceAddrs }()

	validUntil := time.Unix(time.Now().Add(24*time.Hour).Unix(), 0)
	cert, _, err := NewTLSCertPair("test", validUntil, []string{"testtlscert.bogus", "10.1.2.3"})
	if err != nil {
		t.Fatalf("failed with unexpected error: %v", err)
	}
	pemCert, _ := pem.Decode(cert)
	if pemCert == nil {
		t.Fatal("pem.Decode was unable to decode the certificate")
	}
	x509Cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		t.Fatalf("failed to parse the certificate: %v", err)
	}

	for _, want := range []string{"127.0.0.1", "::1", "10.1.2.3"} {
		found := false
		for _, ip := range x509Cert.IPAddresses {
			if ip.Equal(net.ParseIP(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("certificate is missing IP address %s: %v", want, x509Cert.IPAddresses)
		}
	}
	found := false
	for _, name := range x509Cert.DNSNames {
		if name == "testtlscert.bogus" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("certificate is missing DNS name testtlscert.bogus: %v", x509Cert.DNSNames)
	}
}
