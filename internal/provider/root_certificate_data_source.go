package provider

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/scepman/terraform-provider-scepman/internal/clients"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &rootCertificateDataSource{}

func NewRootCertificateDataSource() datasource.DataSource {
	return &rootCertificateDataSource{}
}

type rootCertificateDataSource struct {
	client *clients.Client
}

type RootCertificateDataSourceModel struct {
	Pem       types.String `tfsdk:"pem"`
	DerBase64 types.String `tfsdk:"der_base64"`
	ExpiresAt types.String `tfsdk:"expires_at"`
}

func (r *rootCertificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Data source to retrieve the root certificate of a SCEPman installation.",
		Attributes: map[string]schema.Attribute{
			"pem": schema.StringAttribute{
				MarkdownDescription: "Root certificate in PEM format.",
				Computed:            true,
			},
			"der_base64": schema.StringAttribute{
				MarkdownDescription: "Root certificate in DER format (base64 encoded).",
				Computed:            true,
			},
			"expires_at": schema.StringAttribute{
				MarkdownDescription: "Timestamp of the expiration of the certificate.",
				Computed:            true,
			},
		},
	}
}

func (r *rootCertificateDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*clients.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *clients.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *rootCertificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_root_certificate"
}

func (r *rootCertificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RootCertificateDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	certInfo, err := r.client.UnauthenticatedClient.GetRootCaCertificate(ctx)
	if err != nil {
		resp.Diagnostics.AddError("unable to get root certificate", err.Error())
		return
	}

	data.Pem = types.StringValue(string(pem.EncodeToMemory(certInfo.CertificatePem)))
	data.DerBase64 = types.StringValue(base64.StdEncoding.EncodeToString(certInfo.CertificateDer))
	data.ExpiresAt = types.StringValue(certInfo.Certificate.NotAfter.Format(time.RFC3339))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
