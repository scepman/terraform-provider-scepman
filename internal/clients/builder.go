// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clients

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/client/msgraph"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/scepman/terraform-provider-scepman/internal/client/scepman"
	"github.com/scepman/terraform-provider-scepman/internal/common"
)

type ClientBuilder struct {
	AuthConfig       *auth.Credentials
	Environment      *environments.Environment
	ScepmanAppId     string
	ScepmanEndpoint  string
	PartnerID        string
	TerraformVersion string
	ProviderVersion  string
}

// Build is a helper method which returns a fully instantiated *Client based on the auth Config's current settings.
func (b *ClientBuilder) Build(ctx context.Context) (*Client, error) {
	// client declarations:
	client := Client{
		TenantID:         b.AuthConfig.TenantID,
		ClientID:         b.AuthConfig.ClientID,
		TerraformVersion: b.TerraformVersion,
	}

	if b.AuthConfig == nil {
		return nil, fmt.Errorf("building client: AuthConfig is nil")
	}

	scepManEnv := environments.NewApiEndpoint("scepman", b.ScepmanEndpoint, &b.ScepmanAppId).WithResourceIdentifier(b.ScepmanAppId)

	authorizer, err := auth.NewAuthorizerFromCredentials(ctx, *b.AuthConfig, scepManEnv)
	if err != nil {
		return nil, fmt.Errorf("unable to build authorize for SCEPman: %+v", err)
	}

	client.Environment = b.AuthConfig.Environment
	client.ScepmanEndpoint = b.ScepmanEndpoint
	client.ScepmanEnv = scepManEnv

	// Obtain the tenant ID from Azure CLI
	realAuthorizer := authorizer
	if cache, ok := authorizer.(*auth.CachedAuthorizer); ok {
		realAuthorizer = cache.Source
	}
	if cli, ok := realAuthorizer.(*auth.AzureCliAuthorizer); ok {
		if cli.TenantID == "" {
			return nil, fmt.Errorf("azure-cli could not determine tenant ID to use")
		}
		client.TenantID = cli.TenantID
		if clientId, ok := environments.PublishedApis["MicrosoftAzureCli"]; ok && clientId != "" {
			client.ClientID = clientId
		}
	}

	o := &common.ClientOptions{
		Authorizer:  authorizer,
		Environment: client.Environment,
		TenantID:    client.TenantID,

		TerraformVersion: client.TerraformVersion,
		ProviderVersion:  b.ProviderVersion,
	}

	client.ScepmanClient, err = scepman.NewClient(scepManEnv)
	if err != nil {
		return nil, fmt.Errorf("unable to build scepman client: %+v", err)
	}
	o.Configure(client.ScepmanClient)

	authorizerGraph, err := auth.NewAuthorizerFromCredentials(ctx, *b.AuthConfig, b.Environment.MicrosoftGraph)
	if err != nil {
		return nil, fmt.Errorf("unable to build authorizer for Microsoft Graph: %+v", err)
	}
	og := &common.ClientOptions{
		Authorizer:  authorizerGraph,
		Environment: *b.Environment,
		TenantID:    client.TenantID,

		TerraformVersion: client.TerraformVersion,
		ProviderVersion:  b.ProviderVersion,
	}
	client.GraphClient, err = msgraph.NewClient(b.Environment.MicrosoftGraph, "", "beta")
	if err != nil {
		return nil, fmt.Errorf("unable to build graph client: %+v", err)
	}
	og.ConfigureGraph(client.GraphClient)

	return &client, nil
}
