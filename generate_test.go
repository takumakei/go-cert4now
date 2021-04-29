package cert4now_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/takumakei/go-cert4now"
)

func TestGenerate(t *testing.T) {
	cert, err := cert4now.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := cert4now.WriteCertificate(&buf, cert); err != nil {
		t.Fatal(err)
	}
	if err := cert4now.WritePrivateKey(&buf, cert); err != nil {
		t.Fatal(err)
	}
	load, err := tls.X509KeyPair(buf.Bytes(), buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cert, load); diff != "" {
		t.Fatalf("-want +got\n%s", diff)
	}
}

func TestGenerate_chain(t *testing.T) {
	rootCA, err := cert4now.Generate(
		cert4now.CommonName("My Root CA"),
		cert4now.AddDate(20, 0, 0),
		cert4now.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		cert4now.ExtKeyUsage(),
		cert4now.IsCA(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := cert4now.Generate(
		cert4now.Authority(rootCA),
		cert4now.CommonName("My CA"),
		cert4now.AddDate(20, 0, 0),
		cert4now.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		cert4now.ExtKeyUsage(),
		cert4now.IsCA(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := cert4now.Generate(
		cert4now.Authority(ca),
		cert4now.CommonName("www.example.com"),
		cert4now.IsCA(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	r, err := x509.ParseCertificate(rootCA.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	i, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	l, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	err = l.CheckSignatureFrom(i)
	if err != nil {
		t.Fatal(err)
	}
	err = i.CheckSignatureFrom(r)
	if err != nil {
		t.Fatal(err)
	}
}
