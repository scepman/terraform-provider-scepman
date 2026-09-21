# Terraform Provider for SCEPman

A Terraform provider for managing [SCEPman](https://www.scepman.com/) PKI resources.
This provider is still in very early stages of development. 
Report any issues or feature requests on the [issue tracker](https://github.com/scepman/terraform-provider-scepman/issues).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24 (for building from source)

## Installation

The provider is available on the [Terraform Registry](https://registry.terraform.io/providers/scepman/scepman).

```hcl
terraform {
  required_providers {
    scepman = {
      source  = "scepman/scepman"
    }
  }
}
```

## Usage

Configure the provider in your Terraform configuration:

```hcl
provider "scepman" {
  # Configuration options
}
```

## Building from Source

```shell
git clone git@github.com:scepman/terraform-provider-scepman.git
cd terraform-provider-scepman
go install
```

## Development

Run local unit and TLS regression tests with `go test ./...`. These tests do not
need a SCEPman deployment or credentials. Put OpenSSL 3.x on `PATH` to include the
real TLS renegotiation test (skipped if unavailable or a different major version
is found). CI checks this prerequisite before running the tests.

Generate documentation:

```shell
make generate
```

Run acceptance tests:

```shell
make testacc
```

**Note:** Acceptance tests create real resources.

## License

See [LICENSE](LICENSE) for details.
