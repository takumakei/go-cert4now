package cert4now

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"os"
)

// WriteCertificate writes the certificate into w in PEM format.
func WriteCertificate(w io.Writer, cert tls.Certificate) error {
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
}

// WriteCertificateFile writes the certificate into the file of filename in PEM format.
func WriteCertificateFile(filename string, cert tls.Certificate, perm fs.FileMode) error {
	p, err := EncodeCertificateToPEM(cert)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, p, perm)
}

// EncodeCertificateToPEM encode the certificate of cert into PEM format.
func EncodeCertificateToPEM(cert tls.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	err := WriteCertificate(&buf, cert)
	return buf.Bytes(), err
}

// WritePrivateKey writes the private key into w in PEM format.
func WritePrivateKey(w io.Writer, cert tls.Certificate) error {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

// WritePrivateKeyFile writes the private key into the file of filename in PEM format.
func WritePrivateKeyFile(filename string, cert tls.Certificate, perm fs.FileMode) error {
	p, err := EncodePrivateKeyToPEM(cert)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, p, perm)
}

// EncodePrivateKeyToPEM encodes the private key of cert into PEM format.
func EncodePrivateKeyToPEM(cert tls.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	err := WritePrivateKey(&buf, cert)
	return buf.Bytes(), err
}
