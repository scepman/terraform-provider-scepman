terraform {
  required_providers {
    scepman = {
      source  = "scepman/scepman"
      version = ">= 0.0.0"
    }
  }
}

provider "scepman" {
  endpoint = "https://scepman.example.com"
  app_id   = "00000000-0000-0000-0000-000000000000"
}