variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name used for resource naming"
  type        = string
  default     = "threatwatch"
}

variable "abuseipdb_api_key" {
  description = "AbuseIPDB API key (store in Terraform Cloud or pass via -var)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "otx_api_key" {
  description = "AlienVault OTX API key (store in Terraform Cloud or pass via -var)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "task_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate task memory in MiB"
  type        = number
  default     = 512
}

variable "desired_count" {
  description = "Number of ECS task replicas"
  type        = number
  default     = 1
}
