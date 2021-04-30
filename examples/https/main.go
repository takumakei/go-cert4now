package main

import (
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/takumakei/go-cert4now"
	"github.com/takumakei/go-exit"
)

var (
	serverHost         string
	serverPort         int
	insecureSkipVerify bool
)

func main() {
	exit.Exit(run())
}

func run() error {
	flag.StringVar(&serverHost, "h", "127.0.0.1", "host")
	flag.IntVar(&serverPort, "p", 8443, "port")
	flag.BoolVar(&insecureSkipVerify, "i", false, "[CLIENT] insecureSkipVerify")
	flag.Parse()
	if arg0 := flag.Arg(0); arg0 != "" {
		cmds := map[string]func() error{
			"server": server,
			"client": client,
			"help":   usage,
		}
		var cmd []string
		for v := range cmds {
			if strings.HasPrefix(v, arg0) {
				cmd = append(cmd, v)
			}
		}
		if len(cmd) == 1 {
			return cmds[cmd[0]]()
		}
	}
	usage()
	return exit.Status(1)
}

func usage() error {
	fmt.Println("usage: https [server|client]")
	return nil
}

func server() error {
	cert, err := cert4now.Generate(
		cert4now.Names(serverHost),
		cert4now.ECDSA(elliptic.P384()),
	)
	if err != nil {
		return err
	}
	if err := cert4now.WriteCertificateFile("cert.pem", cert, 0644); err != nil {
		return err
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("foo", "FOO")
		w.Header().Add("foo", "BAR")
		fmt.Fprintln(w, "hello world")
	})
	srv := &http.Server{
		Addr: fmt.Sprintf("%s:%d", serverHost, serverPort),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	fmt.Println("listen", serverHost, serverPort)
	return srv.ListenAndServeTLS("", "")
}

func client() error {
	rootCAs := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		return err
	}
	if !rootCAs.AppendCertsFromPEM(pemCerts) {
		return errors.New("failed to load cert.pem")
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%d/", serverHost, serverPort))
	if err != nil {
		return err
	}
	body, err := readBody(resp.Body)
	if err != nil {
		return err
	}

	fmt.Println(resp.Proto, resp.Status)
	for _, k := range sortKeys(resp.Header) {
		for _, v := range resp.Header[k] {
			fmt.Printf("%s: %v\n", k, v)
		}
	}
	fmt.Println()

	fmt.Println(string(body))

	return nil
}

func readBody(r io.ReadCloser) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

func sortKeys(h http.Header) []string {
	a := make([]string, 0, len(h))
	for k := range h {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}
