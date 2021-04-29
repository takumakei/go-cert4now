package cert4now

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Generate generates a new certificate.
func Generate(options ...Option) (cert tls.Certificate, err error) {
	p := &param{
		keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	err = p.apply(options...)
	if err != nil {
		return
	}

	var skid []byte
	skid, err = calculateSKID(p.signer.Public())
	if err != nil {
		return
	}

	var akid []byte
	authorityKey := p.authorityKey
	if authorityKey == nil {
		authorityKey = p.signer
	} else {
		akid, err = calculateSKID(authorityKey.Public())
		if err != nil {
			return
		}
	}

	template := &x509.Certificate{
		SerialNumber: p.serialNumber,
		Subject:      pkix.Name{CommonName: p.commonName},
		NotBefore:    p.notBefore,
		NotAfter:     p.notAfter,
		KeyUsage:     p.keyUsage,
		ExtKeyUsage:  p.extKeyUsage,

		BasicConstraintsValid: p.basicConstraintsValid,
		IsCA:                  p.isCA,

		SubjectKeyId:   skid,
		AuthorityKeyId: akid,

		DNSNames:       p.dnsNames,
		EmailAddresses: p.emailAddresses,
		IPAddresses:    p.ipAddresses,
	}

	authority := p.authority
	if authority == nil {
		authority = template
	}

	var der []byte
	der, err = x509.CreateCertificate(rand.Reader, template, authority, p.signer.Public(), authorityKey)
	if err != nil {
		return
	}

	cert.Certificate = [][]byte{der}
	cert.PrivateKey = p.signer

	if len(p.chain) > 0 {
		cert.Certificate = append(cert.Certificate, p.chain...)
	}

	return
}

func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
}
