package http

import (
	"crypto"
	"crypto/x509"
	"hash"

	"github.com/bodgit/ntlmssp"
)

func signatureAlgorithmHash(algo x509.SignatureAlgorithm) crypto.Hash {
	for _, details := range []struct {
		algo x509.SignatureAlgorithm
		hash crypto.Hash
	}{
		{x509.MD2WithRSA, crypto.Hash(0)},
		{x509.MD5WithRSA, crypto.MD5},
		{x509.SHA1WithRSA, crypto.SHA1},
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.DSAWithSHA1, crypto.SHA1},
		{x509.DSAWithSHA256, crypto.SHA256},
		{x509.ECDSAWithSHA1, crypto.SHA1},
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.ECDSAWithSHA512, crypto.SHA512},
		{x509.SHA256WithRSAPSS, crypto.SHA256},
		{x509.SHA384WithRSAPSS, crypto.SHA384},
		{x509.SHA512WithRSAPSS, crypto.SHA512},
	} {
		if details.algo == algo {
			return details.hash
		}
	}
	return crypto.Hash(0)
}

func generateCertificateHash(cert *x509.Certificate) []byte {
	algorithm := signatureAlgorithmHash(cert.SignatureAlgorithm)

	var hash hash.Hash

	switch algorithm {
	case crypto.Hash(0):
		return nil
	case crypto.MD5, crypto.SHA1:
		hash = crypto.SHA256.New()
	default:
		hash = algorithm.New()
	}

	hash.Write(cert.Raw)

	return hash.Sum(nil)
}

func generateChannelBindings(cert *x509.Certificate) *ntlmssp.ChannelBindings {
	b := generateCertificateHash(cert)
	if b == nil {
		return nil
	}

	return &ntlmssp.ChannelBindings{
		ApplicationData: concat([]byte(ntlmssp.TLSServerEndPoint+":"), b),
	}
}
