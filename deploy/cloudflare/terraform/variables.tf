variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "zone_id" {
  description = "Cloudflare zone ID for WAF ruleset"
  type        = string
}

variable "r2_bucket_name" {
  description = "R2 bucket for ebi data"
  type        = string
  default     = "ebi-data"
}

variable "r2_public_domain" {
  description = "Production custom domain for static R2 reads (for example, log.example.com)"
  type        = string
}

variable "rate_limit_threshold" {
  description = "Requests per 10s allowed per IP to POST /v1/records"
  type        = number
  default     = 10
}

variable "rate_limit_action" {
  description = "Action for rate limit: block, challenge, or js_challenge"
  type        = string
  default     = "block"
}
