// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package authority

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/application/paths"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/agent/errors"
	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/core/logger"
)

// CertificateAuthority is an abstraction for common certificate authority
// unique for process
type CertificateAuthority struct {
	caCert     *x509.Certificate
	privateKey crypto.PrivateKey
	caPEM      []byte
}

// Pair is a x509 Key/Cert pair
type Pair struct {
	Crt         []byte
	Key         []byte
	Certificate *tls.Certificate
}

// NewCA creates a new certificate authority capable of generating child certificates
func NewCA(l *logger.Logger) (*CertificateAuthority, error) {
	checkBinary(l, "newCA.1")
	ca := &x509.Certificate{
		DNSNames:     []string{"localhost"},
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"elastic-fleet"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	checkBinary(l, "newCA.2")
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	checkBinary(l, "newCA.3")
	publicKey := &privateKey.PublicKey
	checkBinary(l, "newCA.4")
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privateKey)
	if err != nil {
		log.Println("create ca failed", err)
		return nil, errors.New(err, "ca creation failed", errors.TypeSecurity)
	}
	checkBinary(l, "newCA.5")

	var pubKeyBytes, privateKeyBytes []byte

	certOut := bytes.NewBuffer(pubKeyBytes)
	keyOut := bytes.NewBuffer(privateKeyBytes)

	checkBinary(l, "newCA.6")
	// Public key
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		return nil, errors.New(err, "signing ca certificate", errors.TypeSecurity)
	}

	checkBinary(l, "newCA.7")
	// Private key
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		return nil, errors.New(err, "generating ca private key", errors.TypeSecurity)
	}

	checkBinary(l, "newCA.8")
	// prepare tls
	caPEM := certOut.Bytes()
	caTLS, err := tls.X509KeyPair(caPEM, keyOut.Bytes())
	if err != nil {
		return nil, errors.New(err, "generating ca x509 pair", errors.TypeSecurity)
	}

	checkBinary(l, "newCA.9")
	caCert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		return nil, errors.New(err, "generating ca private key", errors.TypeSecurity)
	}

	checkBinary(l, "newCA.10")
	return &CertificateAuthority{
		privateKey: caTLS.PrivateKey,
		caCert:     caCert,
		caPEM:      caPEM,
	}, nil
}

// GeneratePair generates child certificate
func (c *CertificateAuthority) GeneratePair() (*Pair, error) {
	return c.GeneratePairWithName("localhost")
}

// GeneratePairWithName generates child certificate with provided name as the common name.
func (c *CertificateAuthority) GeneratePairWithName(name string) (*Pair, error) {
	// Prepare certificate
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		DNSNames:     []string{name},
		Subject: pkix.Name{
			Organization: []string{"elastic-fleet"},
			CommonName:   name,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	// Sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, c.caCert, publicKey, c.privateKey)
	if err != nil {
		return nil, errors.New(err, "signing certificate", errors.TypeSecurity)
	}

	var pubKeyBytes, privateKeyBytes []byte

	certOut := bytes.NewBuffer(pubKeyBytes)
	keyOut := bytes.NewBuffer(privateKeyBytes)

	// Public key
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return nil, errors.New(err, "generating public key", errors.TypeSecurity)
	}

	// Private key
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		return nil, errors.New(err, "generating private key", errors.TypeSecurity)
	}

	// TLS Certificate
	tlsCert, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		return nil, errors.New(err, "creating TLS certificate", errors.TypeSecurity)
	}

	return &Pair{
		Crt:         certOut.Bytes(),
		Key:         keyOut.Bytes(),
		Certificate: &tlsCert,
	}, nil
}

// Crt returns crt cert of certificate authority
func (c *CertificateAuthority) Crt() []byte {
	return c.caPEM
}

func checkBinary(log *logger.Logger, point string) {
	pid := os.Getpid()
	fn := filepath.Join(paths.Top(), paths.BinaryName)
	_, err := os.Stat(fn)
	suffix := "ok"

	if os.IsNotExist(err) {
		suffix = "not found"
	}

	log.Errorf(">>> [%d].%s %s %s", point, pid, fn, suffix)
}
