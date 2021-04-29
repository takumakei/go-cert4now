Certificate for now
======================================================================

Purpose
----------------------------------------------------------------------

Easily generate a certificate for the time being, usable on a TLS-enabled server.


Example
----------------------------------------------------------------------

### Generating a self signed certificate, then saving it into file.

``` go
cert, _ := cert4now.Generate()
cert4now.WritePrivateKeyFile("cert.key", cert, 0600)
cert4now.WriteCertificateFile("cert.crt", cert, 0644)
```

### Generating a root CA, an intermediate CA and a leaf certificate.

``` go
rootCA, _ := cert4now.Generate(
	cert4now.CommonName("My Root CA"),
	cert4now.AddDate(20, 0, 0),
	cert4now.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	cert4now.ExtKeyUsage(),
	cert4now.IsCA(true),
)

ca, _ := cert4now.Generate(
	cert4now.Authority(rootCA),
	cert4now.CommonName("My CA"),
	cert4now.AddDate(20, 0, 0),
	cert4now.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
	cert4now.ExtKeyUsage(),
	cert4now.IsCA(true),
)

cert, _ := cert4now.Generate(
	cert4now.Authority(ca),
	cert4now.CommonName("www.example.com"),
	cert4now.IsCA(false),
)
```
