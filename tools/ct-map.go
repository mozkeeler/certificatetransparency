// This is an example program that demonstrates processing certificates from a
// log entries file. It looks for certificates that contain ".corp" names and
// prints them to stdout.

package main

import (
	"crypto/x509"
	//"encoding/pem"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/mozkeeler/certificatetransparency"
	"os"
	"strings"
	"sync"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log entries file>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	in, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer in.Close()

	entriesFile := certificatetransparency.EntriesFile{in}

	outputLock := new(sync.Mutex)

	// Dump
	// - csv file of OCSP urls, one per line
	// - csv file of CRL sets, one per line
	// - CNs and subjectAltName for compatibility testing

	entriesFile.Map(func(ent *certificatetransparency.EntryAndPosition, err error) {
		if err != nil {
			return
		}

		cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
		if err != nil {
			return
		}

		dump := true
		for _, san := range cert.DNSNames {
			if strings.HasSuffix(san, ".corp") {
				dump = true
			}
		}
		if dump {
			outputLock.Lock()
			fmt.Printf("CN:%s\n", cert.Subject.CommonName)
			fmt.Printf("ISSUER:%s\n", cert.Issuer.CommonName)
			hasher := sha1.New()
			sha256hasher := sha256.New()
			hasher.Write(cert.RawSubjectPublicKeyInfo)
			sha256hasher.Write(cert.RawSubjectPublicKeyInfo)
			fmt.Printf("sha1/%s\n", base64.StdEncoding.EncodeToString(hasher.Sum(nil)))
			fmt.Printf("sha256/%s\n", base64.StdEncoding.EncodeToString(sha256hasher.Sum(nil)))
			for _, san := range cert.DNSNames {
				fmt.Printf("DNS:%s\n", san)
			}
			for _, san := range cert.CRLDistributionPoints {
				fmt.Printf("CRL:%s\n", san)
			}
			for _, san := range cert.OCSPServer {
				fmt.Printf("OCSP:%s\n", san)
			}
			outputLock.Unlock()
		}
	})
}
