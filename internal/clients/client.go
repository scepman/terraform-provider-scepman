// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clients

import (
	"github.com/hashicorp/go-azure-sdk/sdk/client/msgraph"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/scepman/terraform-provider-scepman/internal/client/scepman"
	"github.com/scepman/terraform-provider-scepman/internal/client/unauthenticated"
)

// Client contains the handles to all the specific Azure AD resource classes' respective clients
type Client struct {
	Environment environments.Environment
	TenantID    string
	ClientID    string

	ScepmanEndpoint string
	ScepmanEnv      environments.Api

	TerraformVersion string

	ScepmanClient         *scepman.Client
	GraphClient           *msgraph.Client
	UnauthenticatedClient *unauthenticated.Client
}
