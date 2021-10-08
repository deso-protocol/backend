variable "pg_password" {
  description = "postgres root user password"
  type        = string
  sensitive   = true
}

variable "sqs_uri" {
  description = "the url of the destination sqs"
  type        = string
  sensitive   = true
}