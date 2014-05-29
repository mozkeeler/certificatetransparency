package certificatetransparency

import "fmt"
import "crypto/x509"
import "encoding/pem"
import "crypto/sha1"
import "crypto/sha256"
import "encoding/base64"
import "bufio"
import "os"

func main() {
	pemFile, err := os.Open(os.Args[1])
	scanner := bufio.NewScanner(bufio.NewReader(pemFile))
	var pemCert []byte
	for scanner.Scan() {
		pemCert = append(pemCert, scanner.Bytes()...)
		pemCert = append(pemCert, '\n')
	}
	fmt.Printf("%s", pemCert)
	block, _ := pem.Decode(pemCert)
	if block == nil {
		fmt.Printf("Can't decode pem\n")
		os.Exit(1)

	}
	if block.Bytes == nil {
		fmt.Printf("No bytes\n")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Can't parse cert\n")
		os.Exit(1)
	}
	hasher := sha1.New()
	sha256hasher := sha256.New()
	hasher.Write(cert.RawSubjectPublicKeyInfo)
	sha256hasher.Write(cert.RawSubjectPublicKeyInfo)
	fmt.Printf("Common name: %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer name: %s\n", cert.Issuer.CommonName)
	fmt.Printf("sha1/%s\n", base64.StdEncoding.EncodeToString(hasher.Sum(nil)))
	fmt.Printf("sha256/%s\n", base64.StdEncoding.EncodeToString(sha256hasher.Sum(nil)))
}
