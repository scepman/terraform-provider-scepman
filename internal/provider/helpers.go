// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func decodeCertificate(clientCertificate string) ([]byte, error) {
	var pfx []byte
	if clientCertificate != "" {
		out := make([]byte, base64.StdEncoding.DecodedLen(len(clientCertificate)))
		n, err := base64.StdEncoding.Decode(out, []byte(clientCertificate))
		if err != nil {
			return pfx, fmt.Errorf("could not decode client certificate data: %v", err)
		}
		pfx = out[:n]
	}
	return pfx, nil
}

// getOidcToken resolves the OIDC assertion token, reading it from a file when
// oidcTokenFilePath is set. If both a direct token and a file are provided,
// their contents must match.
func getOidcToken(oidcToken string, oidcTokenFilePath string) (string, error) {
	if oidcTokenFilePath != "" {
		fileToken, err := os.ReadFile(oidcTokenFilePath)
		if err != nil {
			return "", fmt.Errorf("reading OIDC token from file %q: %v", oidcTokenFilePath, err)
		}

		fileTokenStr := strings.TrimSpace(string(fileToken))
		if oidcToken != "" && oidcToken != fileTokenStr {
			return "", fmt.Errorf("mismatch between supplied OIDC token and supplied OIDC token file contents - please either remove one or ensure they match")
		}

		if fileTokenStr != "" {
			oidcToken = fileTokenStr
		}
	}

	return oidcToken, nil
}

func validateAndMarshalCsr(diag *diag.Diagnostics, csr types.String) ([]byte, error) {
	block, rest := pem.Decode([]byte(csr.ValueString()))
	if block == nil {
		diag.AddAttributeError(path.Root("csr"), "unable to decode PEM block", string(rest))
		return nil, fmt.Errorf("unable to decode PEM block")
	}
	if len(rest) > 0 {
		diag.AddAttributeError(path.Root("csr"), "trailing data after PEM block", string(rest))
		return nil, fmt.Errorf("trailing data after PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		diag.AddAttributeError(path.Root("csr"), "invalid PEM block type", block.Type)
		return nil, fmt.Errorf("invalid PEM block type")
	}

	reqPayload := make([]byte, base64.StdEncoding.EncodedLen(len(block.Bytes)))
	base64.StdEncoding.Encode(reqPayload, block.Bytes)

	return reqPayload, nil
}
