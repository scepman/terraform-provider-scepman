package types

import (
	"crypto/x509"
	"encoding/pem"
)

type CertificateInfo struct {
	CertificateDer []byte
	CertificatePem *pem.Block
	Certificate    *x509.Certificate
}
