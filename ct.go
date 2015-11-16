// Package certificatetransparency implements some helper functions for reading
// and processing log entries from a Certificate Transparency log.
//
// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-12
package certificatetransparency

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"
)

const (
	logVersion           = 0
	certificateTimestamp = 0
	treeHash             = 1
	hashSHA256           = 4
	sigECDSA             = 3
	sigRSA               = 1
)

// Log represents a public log.
type Log struct {
	Root string
	Key  crypto.PublicKey
}

// NewLog creates a new Log given the base URL of a public key and its public
// key in PEM format.
func NewLog(url, pemPublicKey string) (*Log, error) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil {
		return nil, errors.New("certificatetransparency: no PEM block found in public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	_, ecdsaSucceeded := key.(*ecdsa.PublicKey)
	_, rsaSucceeded := key.(*rsa.PublicKey)
	if !rsaSucceeded && !ecdsaSucceeded {
		return nil, errors.New("certificatetransparency: only ECDSA or RSA keys supported at the current time")
	}

	return &Log{url, key}, nil
}

const pilotKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT
DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==
-----END PUBLIC KEY-----`

const aviatorKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1J
YP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==
-----END PUBLIC KEY-----`

const rocketeerKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1
aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==
-----END PUBLIC KEY-----`

const symantecKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY
4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==
-----END PUBLIC KEY-----`

const izenpeKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+T
ZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==
-----END PUBLIC KEY-----`

const certlyKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2M
NvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==
-----END PUBLIC KEY-----`

const digicertKeyPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCF
RkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==
-----END PUBLIC KEY-----`

const venafiKeyPEM = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OC
dpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym
97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWt
gnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB
8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauC
Fx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5
wQIDAQAB
-----END PUBLIC KEY-----
`

// PilotLog is a *Log representing the pilot log run by Google.
var PilotLog *Log
var AviatorLog *Log
var RocketeerLog *Log
var SymantecLog *Log
var IzenpeLog *Log
var CertlyLog *Log
var DigiCertLog *Log
var VenafiLog *Log

func init() {
	PilotLog, _ = NewLog("https://ct.googleapis.com/pilot", pilotKeyPEM)
	AviatorLog, _ = NewLog("https://ct.googleapis.com/aviator", aviatorKeyPEM)
	RocketeerLog, _ = NewLog("https://ct.googleapis.com/rocketeer", rocketeerKeyPEM)
	SymantecLog, _ = NewLog("https://ct.ws.symantec.com", symantecKeyPEM)
	IzenpeLog, _ = NewLog("https://ct.izenpe.com", izenpeKeyPEM)
	CertlyLog, _ = NewLog("https://log.certly.io", certlyKeyPEM)
	DigiCertLog, _ = NewLog("https://ct1.digicert-ct.com/log", digicertKeyPEM)
	VenafiLog, _ = NewLog("https://ctlog.api.venafi.com/", venafiKeyPEM)
}

// SignedTreeHead contains a parsed signed tree-head structure.
type SignedTreeHead struct {
	Size      uint64    `json:"tree_size"`
	Time      time.Time `json:"-"`
	Hash      []byte    `json:"sha256_root_hash"`
	Signature []byte    `json:"tree_head_signature"`
	Timestamp uint64    `json:"timestamp"`
}

func verifyECDSASignature(key *ecdsa.PublicKey, signatureBytes []byte, digest []byte) error {
	var sig struct {
		R, S *big.Int
	}
	remainingBytes, err := asn1.Unmarshal(signatureBytes, &sig)
	if err != nil {
		return errors.New("certificatetransparency: failed to parse signature: " + err.Error())
	}
	if len(remainingBytes) > 0 {
		return errors.New("certificatetransparency: trailing garbage after signature")
	}
	if !ecdsa.Verify(key, digest, sig.R, sig.S) {
		return errors.New("certificatetransparency: signature verification failed")
	}
	return nil
}

func verifyRSASignature(key *rsa.PublicKey, hash crypto.Hash, signatureBytes []byte, digest []byte) error {
	err := rsa.VerifyPKCS1v15(key, hash, digest, signatureBytes)
	if err != nil {
		return errors.New("certificatetransparency: signature verification failed: " + err.Error())
	}
	return nil
}

// GetSignedTreeHead fetches a signed tree-head and verifies the signature.
func (log *Log) GetSignedTreeHead() (*SignedTreeHead, error) {
	// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-4.3
	resp, err := http.Get(log.Root + "/ct/v1/get-sth")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("certificatetransparency: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("certificatetransparency: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<16 {
		return nil, errors.New("certificatetransparency: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	head := new(SignedTreeHead)
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}

	head.Time = time.Unix(int64(head.Timestamp/1000), int64(head.Timestamp%1000))

	// See https://tools.ietf.org/html/rfc5246#section-4.7
	if len(head.Signature) < 4 {
		return nil, errors.New("certificatetransparency: signature truncated")
	}
	if head.Signature[0] != hashSHA256 {
		return nil, errors.New("certificatetransparency: unknown hash function")
	}
	expectedKeyType := head.Signature[1]
	if expectedKeyType != sigECDSA && expectedKeyType != sigRSA {
		return nil, errors.New("certificatetransparency: unknown signature algorithm")
	}
	signatureBytes := head.Signature[4:]

	// See https://tools.ietf.org/html/draft-laurie-pki-sunlight-09#section-3.5
	signed := make([]byte, 2+8+8+32)
	x := signed
	x[0] = logVersion
	x[1] = treeHash
	x = x[2:]
	binary.BigEndian.PutUint64(x, head.Timestamp)
	x = x[8:]
	binary.BigEndian.PutUint64(x, head.Size)
	x = x[8:]
	copy(x, head.Hash)

	h := sha256.New()
	h.Write(signed)
	digest := h.Sum(nil)

	switch key := log.Key.(type) {
	case *ecdsa.PublicKey:
		if expectedKeyType != sigECDSA {
			return nil, errors.New("certificatetransparency: key type/signature algorithm mismatch")
		}
		err = verifyECDSASignature(key, signatureBytes, digest)
		if err != nil {
			return nil, err
		}
	case *rsa.PublicKey:
		if expectedKeyType != sigRSA {
			return nil, errors.New("certificatetransparency: key type/signature algorithm mismatch")
		}
		err = verifyRSASignature(key, crypto.SHA256, signatureBytes, digest)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("certificatetransparency: unknown key type")
	}

	return head, nil
}

type LogEntryType uint16

const (
	X509Entry    LogEntryType = 0
	PreCertEntry LogEntryType = 1
)

type RawEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

func (ent *RawEntry) writeTo(out io.Writer) error {
	var buf bytes.Buffer
	z, err := flate.NewWriter(&buf, 8)
	if err != nil {
		return err
	}
	if err := binary.Write(z, binary.LittleEndian, uint32(len(ent.LeafInput))); err != nil {
		return err
	}
	if _, err := z.Write(ent.LeafInput); err != nil {
		return err
	}
	if err := binary.Write(z, binary.LittleEndian, uint32(len(ent.ExtraData))); err != nil {
		return err
	}
	if _, err := z.Write(ent.ExtraData); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}

	bytes := buf.Bytes()
	if err := binary.Write(out, binary.LittleEndian, uint32(len(bytes))); err != nil {
		return err
	}
	if _, err := out.Write(bytes); err != nil {
		return err
	}

	return nil
}

type entries struct {
	Entries []RawEntry `json:"entries"`
}

// GetEntries returns a series of consecutive log entries from the starting
// index up to, at most, the end index (which may be included). The log may
// choose to return fewer than the requested number of log entires and this is
// not considered an error.
func (log *Log) GetEntries(start, end uint64) ([]RawEntry, error) {
	resp, err := http.Get(fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", log.Root, start, end))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("certificatetransparency: error from server")
	}
	if resp.ContentLength == 0 {
		return nil, errors.New("certificatetransparency: body unexpectedly missing")
	}
	if resp.ContentLength > 1<<31 {
		return nil, errors.New("certificatetransparency: body too large")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ents entries
	if err := json.Unmarshal(data, &ents); err != nil {
		return nil, err
	}

	return ents.Entries, nil
}

// OperationStatus contains the current state of a large operation (i.e.
// download or tree hash).
type OperationStatus struct {
	// Start contains the requested starting index of the operation.
	Start uint64
	// Current contains the greatest index that has been processed.
	Current uint64
	// Length contains the total number of entries.
	Length uint64
}

func (status OperationStatus) Percentage() float32 {
	total := float32(status.Length - status.Start)
	done := float32(status.Current - status.Start)

	if total == 0 {
		return 100
	}
	return done * 100 / total
}

// DownloadRange downloads log entries from the given starting index till one
// less than upTo. If status is not nil then status updates will be written to
// it until the function is complete, when it will be closed. The log entries
// will be compressed and written to out in a format suitable for using with
// EntriesFile. It returns the new starting index (i.e.  start + the number of
// entries downloaded).
func (log *Log) DownloadRange(out io.Writer, status chan<- OperationStatus, start, upTo uint64) (uint64, error) {
	if status != nil {
		defer close(status)
	}

	done := start
	for done < upTo {
		if status != nil {
			status <- OperationStatus{start, done, upTo}
		}

		max := done + 2000
		if max >= upTo {
			max = upTo - 1
		}
		ents, err := log.GetEntries(done, max)
		if err != nil {
			return done, err
		}

		for _, ent := range ents {
			if err := ent.writeTo(out); err != nil {
				return done, err
			}
			done++
		}
	}

	return done, nil
}
