package scepman

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/pkg/errors"
)

type CertificateInfo struct {
	CertificateDer []byte
	CertificatePem *pem.Block
	Certificate    *x509.Certificate
}

func (c *Client) GetRootCaCertificate(incomingCtx context.Context) (*CertificateInfo, error) {
	ctx, ctxCancel := context.WithTimeout(incomingCtx, 30*time.Second)
	defer ctxCancel()

	req, err := c.NewRequest(ctx, client.RequestOptions{
		ContentType:         "attachment",
		ExpectedStatusCodes: []int{http.StatusOK},
		HttpMethod:          http.MethodGet,
		Path:                "ca",
	})
	if err != nil {
		return nil, errors.Wrap(err, "building request")
	}

	var response *client.Response
	response, err = c.Execute(ctx, req)
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

type RootCreationStatusMessage struct {
	IsSuccess bool   `json:"isSuccess"`
	Message   string `json:"message"`
}

func (c *Client) CreateRootCaCertificate(incomingCtx context.Context) (*RootCreationStatusMessage, error) {
	ctx, ctxCancel := context.WithTimeout(incomingCtx, 30*time.Second)
	defer ctxCancel()

	request, err := c.NewRequest(ctx, client.RequestOptions{
		ContentType:         "application/json",
		ExpectedStatusCodes: []int{http.StatusOK, http.StatusCreated, http.StatusAccepted},
		HttpMethod:          http.MethodPost,
		Path:                "ca/create-root",
	})
	if err != nil {
		return nil, errors.Wrap(err, "building request")
	}

	var response *client.Response
	response, err = c.Execute(ctx, request)
	if err != nil {
		return nil, errors.Wrap(err, "executing request")
	}

	rawResponse, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response body")
	}
	response.Body.Close()

	var scepRes RootCreationStatusMessage
	err = json.Unmarshal(rawResponse, &scepRes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling response")
	}

	return &scepRes, nil
}
