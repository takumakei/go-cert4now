package cert4now

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"
)

// Option represents an option for generating a certificate.
type Option func(*param)

// Subject returns an option of setting the subject.
func Subject(name pkix.Name) Option {
	return func(p *param) {
		p.subject = &name
	}
}

// CommonName returns an option of setting the common name.
func CommonName(name string) Option {
	return func(p *param) {
		if p.subject == nil {
			p.subject = &pkix.Name{}
		}
		p.subject.CommonName = name
	}
}

// SerialNumber returns an option of setting the serial number.
func SerialNumber(serialNumber *big.Int) Option {
	return func(p *param) {
		p.serialNumber = serialNumber
	}
}

// NotBefore returns an option of setting the NotBefore.
func NotBefore(t time.Time) Option {
	return func(p *param) {
		p.notBefore = t
	}
}

// NotAfter returns an option of setting the NotAfter.
func NotAfter(t time.Time) Option {
	return func(p *param) {
		p.notAfter = t
	}
}

// AddDate returns an option of setting the NotAfter, and NotBefore in some case.
func AddDate(years, months, days int) Option {
	return func(p *param) {
		if p.notBefore.IsZero() {
			p.notBefore = time.Now()
		}
		p.notAfter = p.notBefore.AddDate(years, months, days)
	}
}

// Signer returns an option of setting the private key.
func Signer(signer crypto.Signer) Option {
	return func(p *param) {
		p.genSigner = func() (crypto.Signer, error) {
			return signer, nil
		}
	}
}

// RSA returns an option of generating then setting the private key.
func RSA(bits int) Option {
	return func(p *param) {
		p.genSigner = func() (crypto.Signer, error) {
			return rsa.GenerateKey(rand.Reader, bits)
		}
	}
}

// ECDSA returns an option of generating then setting the private key.
func ECDSA(c elliptic.Curve) Option {
	return func(p *param) {
		p.genSigner = func() (crypto.Signer, error) {
			return ecdsa.GenerateKey(c, rand.Reader)
		}
	}
}

// KeyUsage returns an option of setting the KeyUsage.
func KeyUsage(usage x509.KeyUsage) Option {
	return func(p *param) {
		p.keyUsage = usage
	}
}

// ExtKeyUsage returns an option of setting an ExtKeyUsage.
func ExtKeyUsage(usage ...x509.ExtKeyUsage) Option {
	return func(p *param) {
		p.extKeyUsage = usage
	}
}

// DNSNamesReset returns an option of setting the DNSNames.
func DNSNamesReset(names ...string) Option {
	names = filterNonEmptyString(names)
	return func(p *param) {
		p.dnsNames = names
	}
}

// DNSNames returns an option of appending the DNSNames.
func DNSNames(names ...string) Option {
	names = filterNonEmptyString(names)
	return func(p *param) {
		p.dnsNames = append(p.dnsNames, names...)
	}
}

// EmailAddressesReset returns an option of setting the EmailAddresses.
func EmailAddressesReset(emails ...string) Option {
	emails = filterNonEmptyString(emails)
	return func(p *param) {
		p.emailAddresses = emails
	}
}

// EmailAddresses returns an option of appending the EmailAddresses.
func EmailAddresses(emails ...string) Option {
	emails = filterNonEmptyString(emails)
	return func(p *param) {
		p.emailAddresses = append(p.emailAddresses, emails...)
	}
}

// Names returns an option of appending DNSNames and IPAddresses.
// For each of names, the name that success to net.ParseIP is appended to IPAddresses.
// The name that failed to net.ParseIP is appended to DNSNames.
func Names(names ...string) Option {
	return func(p *param) {
		var ips []net.IP
		var dns []string
		for _, v := range names {
			if len(v) > 0 {
				if ip := net.ParseIP(v); ip != nil {
					ips = append(ips, ip)
				} else {
					dns = append(dns, v)
				}
			}
		}
		p.ipAddresses = append(p.ipAddresses, ips...)
		p.dnsNames = append(p.dnsNames, dns...)
	}
}

// IPAddressesReset returns an option of setting the IPAddresses.
func IPAddressesReset(ips ...net.IP) Option {
	ips = filterNonEmptyIP(ips)
	return func(p *param) {
		p.ipAddresses = ips
	}
}

// IPAddresses returns an option of appending the IPAddresses.
func IPAddresses(ips ...net.IP) Option {
	ips = filterNonEmptyIP(ips)
	return func(p *param) {
		p.ipAddresses = append(p.ipAddresses, ips...)
	}
}

// BasicConstraintsValid returns an option of setting the BasicConstraintsValid.
func BasicConstraintsValid(flag bool) Option {
	return func(p *param) {
		p.basicConstraintsValid = flag
	}
}

// IsCA returns an option of setting the IsCA and BasicConstraintsValid.
func IsCA(isCA bool) Option {
	return func(p *param) {
		p.basicConstraintsValid = true
		p.isCA = isCA
	}
}

// ErrInvalidAuthorityKey represents the authority certificate has an invalid private key.
var ErrInvalidAuthorityKey = errors.New("authority's PrivateKey is not type of crypto.Signer")

// Authority returns an option of setting the authority.
func Authority(cert tls.Certificate) Option {
	return func(p *param) {
		var ok bool
		p.authority, p.err = x509.ParseCertificate(cert.Certificate[0])
		if p.err != nil {
			return
		}
		p.authorityKey, ok = cert.PrivateKey.(crypto.Signer)
		if !ok {
			p.err = ErrInvalidAuthorityKey
			return
		}
		p.chain = cert.Certificate
	}
}

func filterNonEmptyString(a []string) []string {
	for i, v := range a {
		if len(v) == 0 {
			b := a[:i]
			for _, v := range a[i+1:] {
				if len(v) > 0 {
					b = append(b, v)
				}
			}
			return b
		}
	}
	return a
}

func filterNonEmptyIP(a []net.IP) []net.IP {
	for i, v := range a {
		if len(v) == 0 {
			b := a[:i]
			for _, v := range a[i+1:] {
				if len(v) > 0 {
					b = append(b, v)
				}
			}
			return b
		}
	}
	return a
}
