terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.22"
    }
  }
  required_version = ">= 1.0"
}

provider "cloudflare" {
  # Use CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY env vars.
  # Never set credentials here.
}

resource "cloudflare_r2_bucket" "ebi" {
  account_id = var.account_id
  name       = var.r2_bucket_name
  location   = "APAC"
}

resource "cloudflare_r2_custom_domain" "ebi" {
  account_id  = var.account_id
  bucket_name = cloudflare_r2_bucket.ebi.name
  domain      = var.r2_public_domain
  zone_id     = var.zone_id
  enabled     = true
  min_tls     = "1.2"
}

resource "cloudflare_ruleset" "ebi_rate_limit" {
  zone_id     = var.zone_id
  name        = "ebi rate limit"
  description = "Rate-limit ebi submission endpoints per IP"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [{
    ref         = "ebi_records_ip_rate_limit"
    action      = var.rate_limit_action
    expression  = "http.host eq \"${var.submit_domain}\" and http.request.method eq \"POST\" and (http.request.uri.path eq \"/v1/records\" or http.request.uri.path eq \"/v1/reports\")"
    description = "Rate limit ebi submission endpoints per IP"
    enabled     = true
    ratelimit = {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = var.rate_limit_threshold
      mitigation_timeout  = 60
      counting_expression = "http.host eq \"${var.submit_domain}\" and http.request.method eq \"POST\" and (http.request.uri.path eq \"/v1/records\" or http.request.uri.path eq \"/v1/reports\")"
    }
  }]
}

resource "cloudflare_ruleset" "ebi_static_cache" {
  zone_id     = var.zone_id
  name        = "ebi static transparency log cache"
  description = "Cache all immutable/content-addressed ebi static log paths while respecting origin Cache-Control"
  kind        = "zone"
  phase       = "http_request_cache_settings"

  rules = [{
    ref         = "ebi_static_log_cache"
    action      = "set_cache_settings"
    expression  = "http.host eq \"${var.r2_public_domain}\" and http.request.method eq \"GET\" and starts_with(http.request.uri.path, \"/v1/\")"
    description = "Make extensionless transparency-log objects cache eligible"
    enabled     = true
    action_parameters = {
      cache = true
      edge_ttl = {
        mode = "respect_origin"
      }
    }
  }]

  depends_on = [cloudflare_r2_custom_domain.ebi]
}

output "r2_bucket_name" {
  value = cloudflare_r2_bucket.ebi.name
}

output "rate_limit_rule_id" {
  value = cloudflare_ruleset.ebi_rate_limit.id
}

output "r2_public_domain" {
  value = cloudflare_r2_custom_domain.ebi.domain
}
