package common

import (
	"github.com/hashicorp/go-azure-sdk/sdk/client"
	"github.com/hashicorp/go-azure-sdk/sdk/odata"
)

type GenericOptions struct {
	ConsistencyLevel *odata.ConsistencyLevel `yaml:"consistencyLevel"`
	Metadata         *odata.Metadata         `yaml:"metadata"`
	Count            *bool                   `yaml:"count"`
	Expand           *odata.Expand           `yaml:"expand"`
	Filter           *string                 `yaml:"filter"`
	Format           *odata.Format           `yaml:"format"`
	OrderBy          *odata.OrderBy          `yaml:"orderBy"`
	Select           *[]string               `yaml:"select"`
	Skip             *int                    `yaml:"skip"`
	Top              *int                    `yaml:"top"`
	Headers          *client.Headers         `yaml:"headers,omitempty"`
}

func (o GenericOptions) ToHeaders() *client.Headers {
	if o.Headers != nil {
		return o.Headers
	}
	return &client.Headers{}
}

func (o GenericOptions) ToOData() *odata.Query {
	out := odata.Query{}
	if o.ConsistencyLevel != nil {
		out.ConsistencyLevel = *o.ConsistencyLevel
	}
	if o.Metadata != nil {
		out.Metadata = *o.Metadata
	}
	if o.Count != nil {
		out.Count = *o.Count
	}
	if o.Expand != nil {
		out.Expand = *o.Expand
	}
	if o.Filter != nil {
		out.Filter = *o.Filter
	}
	if o.Format != nil {
		out.Format = *o.Format
	}
	if o.OrderBy != nil {
		out.OrderBy = *o.OrderBy
	}
	if o.Select != nil {
		out.Select = *o.Select
	}
	if o.Skip != nil {
		out.Skip = *o.Skip
	}
	if o.Top != nil {
		out.Top = *o.Top
	}
	return &out
}

func (o GenericOptions) ToQuery() *client.QueryParams {
	out := client.QueryParams{}

	return &out
}
