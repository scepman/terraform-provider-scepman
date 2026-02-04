// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/scepman/terraform-provider-scepman/internal/clients"
)

// Ensure ScepmanProvider satisfies various provider interfaces.
var _ provider.Provider = &ScepmanProvider{}
var _ provider.ProviderWithFunctions = &ScepmanProvider{}
var _ provider.ProviderWithEphemeralResources = &ScepmanProvider{}
var _ provider.ProviderWithActions = &ScepmanProvider{}

// ScepmanProvider defines the provider implementation.
type ScepmanProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// ScepmanProviderModel describes the provider data model.
type ScepmanProviderModel struct {
	Endpoint                  types.String `tfsdk:"endpoint"`
	AppId                     types.String `tfsdk:"app_id"`
	Environment               types.String `tfsdk:"environment"`
	TenantId                  types.String `tfsdk:"tenant_id"`
	ClientId                  types.String `tfsdk:"client_id"`
	ClientCertificate         types.String `tfsdk:"client_certificate"`
	ClientCertificatePassword types.String `tfsdk:"client_certificate_password"`
	ClientCertificatePath     types.String `tfsdk:"client_certificate_path"`
	ClientSecret              types.String `tfsdk:"client_secret"`
	UseOidc                   types.Bool   `tfsdk:"use_oidc"`
	UseCli                    types.Bool   `tfsdk:"use_cli"`
	UseMsi                    types.Bool   `tfsdk:"use_msi"`
	MsiEndpoint               types.String `tfsdk:"msi_endpoint"`
}

func (p *ScepmanProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "scepman"
	resp.Version = p.version
}

func (p *ScepmanProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The SCEPman provider allows managing SCEPman certificate authority related resources with terraform/opentofu.
It also integrates with Entra Global Secure Access (GSA) to manage TLS Inspection certificates.`,
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "SCEPman API endpoint",
				Required:            true,
			},
			"app_id": schema.StringAttribute{
				MarkdownDescription: "Application ID of the SCEPman-api in the target tenant.",
				Optional:            true,
			},
			"environment": schema.StringAttribute{
				MarkdownDescription: "The cloud environment which should be used. Possible values are: `global` (also `public`), `usgovernmentl4` (also `usgovernment`), `usgovernmentl5` (also `dod`), and `china`. Defaults to `global`. Not used and should not be specified when `metadata_host` is specified.",
				Optional:            true,
			},
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "Tenant ID to use for authenticating SCEPman API requests",
				Optional:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "Client ID to use for authenticating SCEPman API requests",
				Optional:            true,
			},
			"client_certificate": schema.StringAttribute{
				MarkdownDescription: "Base64 encoded PKCS#12 certificate bundle to use when authenticating as a Service Principal using a Client Certificate",
				Optional:            true,
			},
			"client_certificate_password": schema.StringAttribute{
				MarkdownDescription: "Password used to access the Client Certificate",
				Optional:            true,
			},
			"client_certificate_path": schema.StringAttribute{
				MarkdownDescription: "The path to the Client Certificate associated with the Service Principal for use when authenticating as a Service Principal using a Client Certificate",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "Client secret to use for authenticating SCEPman API requests",
				Optional:            true,
			},
			"use_oidc": schema.BoolAttribute{
				MarkdownDescription: "Use OpenID Connect for authentication",
				Optional:            true,
			},
			"use_cli": schema.BoolAttribute{
				MarkdownDescription: "Use Azure CLI for authentication",
				Optional:            true,
			},
			"use_msi": schema.BoolAttribute{
				MarkdownDescription: "Use Managed Service Identity for authentication",
				Optional:            true,
			},
			"msi_endpoint": schema.StringAttribute{
				MarkdownDescription: "The URL of the Managed Service Identity (MSI) endpoint, if different from the Azure public cloud",
				Optional:            true,
			},
		},
	}
}

func getAttributeString(configVal types.String, envNames ...string) string {
	for _, e := range envNames {
		if v := os.Getenv(e); v != "" {
			return v
		}
	}
	return configVal.ValueString()
}

func getAttributeBool(configVal types.Bool, envNames ...string) bool {
	for _, e := range envNames {
		if v := os.Getenv(e); v != "" {
			return v == "true"
		}
	}
	return configVal.ValueBool()
}

func (p *ScepmanProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ScepmanProviderModel
	var env *environments.Environment
	var certData []byte
	var err error

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Configuration values are now available.
	// if data.Endpoint.IsNull() { /* ... */ }

	if data.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Unknown SCEPman endpoint",
			"A SCEPman endpoint must be provided.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := getAttributeString(data.Endpoint, "SCEPMAN_ENDPOINT")
	appId := getAttributeString(data.AppId, "SCEPMAN_APP_ID")
	environment := getAttributeString(data.Environment, "SCEPMAN_ENVIRONMENT", "ARM_ENVIRONMENT")
	if environment == "" {
		environment = "global"
	}

	encodedCert := getAttributeString(data.ClientCertificate, "SCEPMAN_CLIENT_CERTIFICATE", "ARM_CLIENT_CERTIFICATE")
	if encodedCert != "" {
		certData, err = decodeCertificate(encodedCert)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("client_certificate"),
				"Unable to decode client certificate",
				err.Error(),
			)
		}
	}

	tenantId := getAttributeString(data.TenantId, "SCEPMAN_TENANT_ID", "ARM_TENANT_ID")
	clientId := getAttributeString(data.ClientId, "SCEPMAN_CLIENT_ID", "ARM_CLIENT_ID")
	clientSecret := getAttributeString(data.ClientSecret, "SCEPMAN_CLIENT_SECRET", "ARM_CLIENT_SECRET")
	clientCertificatePath := getAttributeString(data.ClientCertificatePath, "SCEPMAN_CLIENT_CERTIFICATE_PATH", "ARM_CLIENT_CERTIFICATE_PATH")
	clientCertificatePassword := getAttributeString(data.ClientCertificatePassword, "SCEPMAN_CLIENT_CERTIFICATE_PASSWORD", "ARM_CLIENT_CERTIFICATE_PASSWORD")
	msiEndpoint := getAttributeString(data.MsiEndpoint, "SCEPMAN_MSI_ENDPOINT", "ARM_MSI_ENDPOINT")
	useAzCli := getAttributeBool(data.UseCli, "SCEPMAN_USE_CLI", "ARM_USE_CLI")
	useOidc := getAttributeBool(data.UseOidc, "SCEPMAN_USE_OIDC", "ARM_USE_OIDC")
	useMsi := getAttributeBool(data.UseMsi, "SCEPMAN_USE_MSI", "ARM_USE_MSI")

	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Missing SCEPman endpoint",
			"A SCEPman endpoint must be provided, either setting it as SCEPMAN_ENDPOINT environment variable or in the provider configuration.",
		)
	}

	env, err = environments.FromName(environment)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("environment"),
			"Invalid environment",
			err.Error(),
		)
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	authConfig := &auth.Credentials{
		Environment: *env,
		ClientID:    clientId,
		TenantID:    tenantId,

		ClientCertificateData:     certData,
		ClientCertificatePath:     clientCertificatePath,
		ClientCertificatePassword: clientCertificatePassword,
		ClientSecret:              clientSecret,

		CustomManagedIdentityEndpoint: msiEndpoint,

		EnableAuthenticatingUsingAzureCLI:          useAzCli,
		EnableAuthenticatingUsingClientCertificate: true,
		EnableAuthenticatingUsingClientSecret:      true,
		EnableAuthenticatingUsingManagedIdentity:   useMsi,
		EnableAuthenticationUsingGitHubOIDC:        useOidc,
		EnableAuthenticationUsingADOPipelineOIDC:   useOidc,
		EnableAuthenticationUsingOIDC:              useOidc,
	}

	clientBuilder := clients.ClientBuilder{
		Environment:      env,
		AuthConfig:       authConfig,
		TerraformVersion: p.version,
		ScepmanEndpoint:  endpoint,
		ScepmanAppId:     appId,
		ProviderVersion:  p.version,
	}

	client, err := clientBuilder.Build(ctx)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Unable to build authenticated API clients. Endpoints requiring authentication will not work.",
			fmt.Sprintf("An error was encountered trying to build authenticated API clients: %s", err.Error()),
		)
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *ScepmanProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRootCertificateResource,
		NewCertificateFromCsrResource,
		NewGsaTlsInspectionCertificateResource,
	}
}

func (p *ScepmanProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *ScepmanProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewRootCertificateDataSource,
	}
}

func (p *ScepmanProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func (p *ScepmanProvider) Actions(ctx context.Context) []func() action.Action {
	return []func() action.Action{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ScepmanProvider{
			version: version,
		}
	}
}
