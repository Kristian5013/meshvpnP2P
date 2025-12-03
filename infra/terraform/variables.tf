# MeshVPN Terraform Variables

variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "meshvpn"
}

variable "environment" {
  description = "Environment (prod, staging, dev)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be prod, staging, or dev."
  }
}

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "regions" {
  description = "List of regions to deploy exit nodes"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"]
}

variable "vpn_port" {
  description = "UDP port for VPN traffic"
  type        = number
  default     = 51820
}

variable "instance_type" {
  description = "EC2 instance type for exit nodes"
  type        = string
  default     = "t3.medium"
}

variable "desired_capacity" {
  description = "Desired number of exit nodes per region"
  type        = number
  default     = 2
}

variable "min_capacity" {
  description = "Minimum number of exit nodes per region"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum number of exit nodes per region"
  type        = number
  default     = 10
}

variable "management_cidrs" {
  description = "CIDR blocks allowed to SSH to exit nodes"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # Replace with your management network
}

variable "enable_enhanced_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "enable_spot_instances" {
  description = "Use spot instances for cost savings (not recommended for prod)"
  type        = bool
  default     = false
}

variable "spot_price" {
  description = "Maximum spot price (only used if enable_spot_instances is true)"
  type        = string
  default     = "0.05"
}

variable "key_pair_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
  default     = ""
}

variable "enable_ipv6" {
  description = "Enable IPv6 support"
  type        = bool
  default     = false
}

variable "custom_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
