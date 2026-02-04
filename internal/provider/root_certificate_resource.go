package provider

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/scepman/terraform-provider-scepman/internal/clients"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &rootCertificateResource{}
var _ resource.ResourceWithConfigure = &rootCertificateResource{}

func NewRootCertificateResource() resource.Resource {
	return &rootCertificateResource{}
}

type rootCertificateResource struct {
	client *clients.Client
}

type RootCertificateResourceModel struct {
	StatusMessage types.String `tfsdk:"status_message"`
	LastUpdated   types.String `tfsdk:"last_updated"`
	ExpiresAt     types.String `tfsdk:"expires_at"`
	Pem           types.String `tfsdk:"pem"`
	DerBase64     types.String `tfsdk:"der_base64"`
}

func (r *rootCertificateResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*clients.Client)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *clients.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = c
}

func (r *rootCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_root_certificate"
}

func (r *rootCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Resource to trigger the initial creation of the root certificate for SCEPman.

This resource has no configurable attributes and cannot be modified. Deletion is a no-op.`,
		Attributes: map[string]schema.Attribute{
			"status_message": schema.StringAttribute{
				MarkdownDescription: "Status message of the root certificate creation request.",
				Computed:            true,
			},
			"last_updated": schema.StringAttribute{
				MarkdownDescription: "Timestamp of the last update of the certificate.",
				Computed:            true,
			},
			"expires_at": schema.StringAttribute{
				MarkdownDescription: "Timestamp of the expiration of the certificate.",
				Computed:            true,
			},
			"pem": schema.StringAttribute{
				MarkdownDescription: "Root certificate in PEM format.",
				Computed:            true,
			},
			"der_base64": schema.StringAttribute{
				MarkdownDescription: "Root certificate in DER format (base64 encoded).",
				Computed:            true,
			},
		},
	}
}
func (r *rootCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data RootCertificateResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

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

func (r *rootCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data RootCertificateResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	rootGenerationStatus, err := r.client.UnauthenticatedClient.CreateRootCaCertificate(ctx)
	if err != nil {
		resp.Diagnostics.AddError("unable to create root certificate", err.Error())
		return
	}

	data.StatusMessage = types.StringValue(rootGenerationStatus.Message)
	data.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))

	time.Sleep(10 * time.Second)

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

func (r *rootCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *rootCertificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}
