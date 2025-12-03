# MeshVPN Terraform Outputs

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table for exit node registry"
  value       = aws_dynamodb_table.exit_nodes.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table"
  value       = aws_dynamodb_table.exit_nodes.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for logs"
  value       = aws_s3_bucket.logs.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.logs.arn
}

output "iam_role_arn" {
  description = "ARN of the IAM role for exit nodes"
  value       = aws_iam_role.exit_node.arn
}

output "instance_profile_name" {
  description = "Name of the instance profile"
  value       = aws_iam_instance_profile.exit_node.name
}

output "security_group_id" {
  description = "ID of the exit node security group"
  value       = aws_security_group.exit_node.id
}

output "launch_template_id" {
  description = "ID of the launch template"
  value       = aws_launch_template.exit_node.id
}

output "autoscaling_group_name" {
  description = "Name of the Auto Scaling group"
  value       = aws_autoscaling_group.exit_nodes.name
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.exit_nodes.name
}

output "vpn_port" {
  description = "VPN UDP port"
  value       = var.vpn_port
}

output "deployment_info" {
  description = "Summary of deployment"
  value = {
    environment      = var.environment
    primary_region   = var.primary_region
    instance_type    = var.instance_type
    desired_capacity = var.desired_capacity
    max_capacity     = var.max_capacity
  }
}
