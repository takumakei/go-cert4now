package cert4now_test

import (
	"bytes"
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/takumakei/go-cert4now"
)

func TestWrite(t *testing.T) {
	cert, err := cert4now.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var keyPEM bytes.Buffer
	err = cert4now.WritePrivateKey(&keyPEM, cert)
	if err != nil {
		t.Fatal(err)
	}

	var certPEM bytes.Buffer
	err = cert4now.WriteCertificate(&certPEM, cert)
	if err != nil {
		t.Fatal(err)
	}

	load, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cert, load); diff != "" {
		t.Fatalf("-want +got\n%s", diff)
	}
}

func TestWriteFile(t *testing.T) {
	cert, err := cert4now.Generate()
	if err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := cert4now.WritePrivateKeyFile(keyFile, cert, 0600); err != nil {
		t.Fatal(err)
	}

	certFile := filepath.Join(t.TempDir(), "cert.pem")
	if err := cert4now.WriteCertificateFile(certFile, cert, 0644); err != nil {
		t.Fatal(err)
	}

	load, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cert, load); diff != "" {
		t.Fatalf("-want +got\n%s", diff)
	}
}
