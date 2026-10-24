package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	host      = "test.example.com"
	ip        = "127.0.0.1"
	port      = "8443"
	oldBundle = "old-cacert.pem"
)

func dial(cfg *tls.Config) (string, error) {
	cfg.ServerName = host
	cfg.MinVersion = tls.VersionTLS12
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", ip+":"+port, cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", fmt.Errorf("empty response")
	}
	return strings.SplitN(string(buf[:n]), "\r\n", 2)[0], nil
}

func main() {
	fmt.Printf("Go %s  (%s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Println("fixed releases: go1.27.3, go1.26.10  (CVE-2026-111943)")
	fmt.Println(strings.Repeat("=", 66))

	// -- 1: default system roots --
	fmt.Println("\nTest 1: default verification (system roots)")
	if line, err := dial(&tls.Config{}); err != nil {
		fmt.Printf("  [default] PROTECTED — %v\n", err)
	} else {
		fmt.Printf("  [default] VULNERABLE — %s\n", line)
	}

	// -- 2: old-cacert.pem as RootCAs --
	fmt.Println("\nTest 2: RootCAs = old-cacert.pem (certifi 2026.06.17)")
	data, err := os.ReadFile(oldBundle)
	if err != nil {
		fmt.Printf("  [old-cacert] SKIPPED — %v\n", err)
	} else {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			fmt.Println("  [old-cacert] ERROR — could not parse bundle")
		} else if line, err := dial(&tls.Config{RootCAs: pool}); err != nil {
			fmt.Printf("  [old-cacert] PROTECTED — %v\n", err)
		} else {
			fmt.Printf("  [old-cacert] VULNERABLE — %s\n", line)
		}
	}

	// -- 3: control --
	fmt.Println("\nTest 3: InsecureSkipVerify=true (control: proves network path)")
	if line, err := dial(&tls.Config{InsecureSkipVerify: true}); err != nil {
		fmt.Printf("  [insecure] ERROR — %v (is app.py running?)\n", err)
	} else {
		fmt.Printf("  [insecure] %s\n", line)
	}

	fmt.Println(strings.Repeat("=", 66))
}