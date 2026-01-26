package scepman

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/pkg/errors"
)

func (c *Client) IssueCertificateFromCsr(incomingContext context.Context, csrPayload []byte) (*CertificateInfo, error) {
	ctx, ctxCancel := context.WithTimeout(incomingContext, 1*time.Minute)
	defer ctxCancel()

	request, err := c.NewRequest(ctx, client.RequestOptions{
		ContentType:         "application/octet-stream",
		ExpectedStatusCodes: []int{http.StatusOK},
		HttpMethod:          http.MethodPost,
		Path:                "api/csr",
	})
	if err != nil {
		return nil, errors.Wrap(err, "building request")
	}

	err = request.Marshal(csrPayload)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling request payload")
	}

	var response *client.Response
	response, err = c.Execute(ctx, request)
	if err != nil {
		return nil, errors.Wrap(err, "executing request")
	}

	rawCert, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response body")
	}
	response.Body.Close()

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, errors.Wrap(err, "parsing certificate")
	}

	pemBlock := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   rawCert,
	}

	return &CertificateInfo{
		CertificateDer: rawCert,
		CertificatePem: &pemBlock,
		Certificate:    cert,
	}, nil
}
