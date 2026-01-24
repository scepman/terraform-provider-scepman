resource "scepman_certificate_from_csr" "csr_example" {
  csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIE4TCCAssCAQAwODEcMBoGA1UEAwwTR1NBIEludGVybmV0IEFjY2VzczEYMBYG\n.......\n-----END CERTIFICATE REQUEST-----"
}