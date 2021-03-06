package cert4now

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math"
	"math/big"
	"net"
	"time"
)

type param struct {
	authority    *x509.Certificate
	authorityKey crypto.Signer
	chain        [][]byte

	subject               *pkix.Name
	serialNumber          *big.Int
	genSigner             func() (crypto.Signer, error)
	notBefore             time.Time
	notAfter              time.Time
	keyUsage              x509.KeyUsage
	extKeyUsage           []x509.ExtKeyUsage
	basicConstraintsValid bool
	isCA                  bool

	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP

	err error
}

func (p *param) apply(options ...Option) error {
	for _, option := range options {
		option(p)
		if err := p.err; err != nil {
			return err
		}
	}
	return p.fill()
}

func (p *param) fill() (err error) {
	if p.serialNumber == nil {
		p.serialNumber, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			return
		}
	}

	if p.subject == nil {
		sn := p.serialNumber.Bytes()
		if len(sn) > 3 {
			sn = sn[:3]
		}
		p.subject = &pkix.Name{
			CommonName: "Self Signed Cert " + hex.EncodeToString(sn),
		}
	}

	if p.genSigner == nil {
		RSA(2048)(p)
	}

	if p.notBefore.IsZero() {
		p.notBefore = time.Now()
	}

	if p.notAfter.IsZero() {
		p.notAfter = p.notBefore.AddDate(0, 0, 90)
	}

	return
}
