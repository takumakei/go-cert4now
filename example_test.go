package cert4now_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/oklog/run"
	"github.com/takumakei/go-cert4now"
)

func Example() {
	// Generating a self signed certificate as a CA.
	ca, err := cert4now.Generate(
		cert4now.CommonName("Root CA"),
		cert4now.AddDate(20, 0, 0),
		cert4now.KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign),
		cert4now.ExtKeyUsage(),
		cert4now.IsCA(true),
	)
	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	server := func() (exec func() error, intr func(error)) {
		// Generating a certificate signed by CA for the TLS-enabled http server.
		cert, err := cert4now.Generate(
			cert4now.Authority(ca),
			cert4now.CommonName("Leaf certificate"),
			cert4now.DNSNames("localhost"),
			cert4now.IPs("127.0.0.1"),
			cert4now.IsCA(false),
		)
		if err != nil {
			panic(err)
		}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "hello world")
		})

		srv := http.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}

		exec = func() error {
			return srv.ServeTLS(ln, "", "")
		}

		intr = func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
		}

		return
	}

	client := func() (exec func() error, intr func(error)) {
		exec = func() error {
			ca, err := x509.ParseCertificate(ca.Certificate[0])
			if err != nil {
				return err
			}
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(ca)

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: rootCAs,
						VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
							for i, x := range verifiedChains {
								for j, y := range x {
									fmt.Println(i, j, y.Subject.CommonName)
								}
							}
							return nil
						},
					},
				},
			}

			resp, err := client.Get("https://" + ln.Addr().String())
			if err != nil {
				return err
			}
			p, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			fmt.Println(string(p))
			return nil
		}

		intr = func(error) {}
		return
	}

	var g run.Group
	g.Add(server())
	g.Add(client())
	if err := g.Run(); err != nil {
		panic(err)
	}

	// Output:
	// 0 0 Leaf certificate
	// 0 1 Root CA
	// hello world
}
