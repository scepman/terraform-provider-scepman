package provider

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/scepman/terraform-provider-scepman/internal/clients"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &certificateFromCsrResource{}
var _ resource.ResourceWithConfigure = &certificateFromCsrResource{}

func NewCertificateFromCsrResource() resource.Resource {
	return &certificateFromCsrResource{}
}

type certificateFromCsrResource struct {
	client *clients.Client
}

type CertificateFromCsrModel struct {
	Csr types.String `tfsdk:"csr"`

	LastUpdated types.String `tfsdk:"last_updated"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
	Pem         types.String `tfsdk:"pem"`
	DerBase64   types.String `tfsdk:"der_base64"`
}

func (r *certificateFromCsrResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *certificateFromCsrResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_from_csr"
}

func (r *certificateFromCsrResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Resource to get a SCEPman issued certificate from a CSR.

## Authorization Requirements
To be able to use this resource, the calling service principal must have the following application permissions:
- CSR.Request on the SCEPman API application in the target tenant.
`,
		Attributes: map[string]schema.Attribute{
			"csr": schema.StringAttribute{
				MarkdownDescription: "CSR in PEM format.",
				Required:            true,
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
				MarkdownDescription: "Certificate in PEM format.",
				Computed:            true,
			},
			"der_base64": schema.StringAttribute{
				MarkdownDescription: "Root certificate in DER format (base64 encoded).",
				Computed:            true,
			},
		},
	}
}
func (r *certificateFromCsrResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

func (r *certificateFromCsrResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CertificateFromCsrModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := r.processCsr(ctx, &resp.Diagnostics, &plan)
	if err != nil {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *certificateFromCsrResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var old, plan CertificateFromCsrModel

	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if old.Csr.ValueString() != plan.Csr.ValueString() {
		err := r.processCsr(ctx, &resp.Diagnostics, &plan)
		if err != nil {
			return
		}

		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *certificateFromCsrResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *certificateFromCsrResource) processCsr(ctx context.Context, diag *diag.Diagnostics, plan *CertificateFromCsrModel) error {
	reqPayload, err := validateAndMarshalCsr(diag, plan.Csr)
	if err != nil {
		return err
	}

	certInfo, err := r.client.ScepmanClient.IssueCertificateFromCsr(ctx, reqPayload)
	if err != nil {
		diag.AddError("unable to get root certificate", err.Error())
		return err
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC3339))
	plan.ExpiresAt = types.StringValue(certInfo.Certificate.NotAfter.Format(time.RFC3339))
	plan.Pem = types.StringValue(string(pem.EncodeToMemory(certInfo.CertificatePem)))
	plan.DerBase64 = types.StringValue(base64.StdEncoding.EncodeToString(certInfo.CertificateDer))

	return nil
}
