resource "scepman_gsa_tls_inspection_certificate" "test" {
  common_name       = "GSA-Intermediate-CA-V1"
  organization_name = "MyOrg"
  renew_before      = 650
}