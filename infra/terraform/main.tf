# MeshVPN Exit Node Infrastructure
# Deploys exit nodes across multiple AWS regions

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend for state storage (configure for your environment)
  # backend "s3" {
  #   bucket         = "meshvpn-terraform-state"
  #   key            = "infra/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "meshvpn-terraform-locks"
  # }
}

# Primary region provider
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = {
      Project     = "MeshVPN"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Provider aliases for multi-region deployment
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "MeshVPN"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"

  default_tags {
    tags = {
      Project     = "MeshVPN"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"

  default_tags {
    tags = {
      Project     = "MeshVPN"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"

  default_tags {
    tags = {
      Project     = "MeshVPN"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# DynamoDB table for exit node registry (global table for multi-region)
resource "aws_dynamodb_table" "exit_nodes" {
  name           = "${var.project_name}-exit-nodes-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "node_id"

  attribute {
    name = "node_id"
    type = "S"
  }

  attribute {
    name = "region"
    type = "S"
  }

  global_secondary_index {
    name            = "region-index"
    hash_key        = "region"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-exit-nodes"
  }
}

# S3 bucket for logs
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-logs-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "${var.project_name}-logs"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# IAM role for exit nodes
resource "aws_iam_role" "exit_node" {
  name = "${var.project_name}-exit-node-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "exit_node_dynamodb" {
  name = "dynamodb-access"
  role = aws_iam_role.exit_node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.exit_nodes.arn,
          "${aws_dynamodb_table.exit_nodes.arn}/index/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "exit_node_s3" {
  name = "s3-access"
  role = aws_iam_role.exit_node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "exit_node_cloudwatch" {
  name = "cloudwatch-access"
  role = aws_iam_role.exit_node.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "exit_node" {
  name = "${var.project_name}-exit-node-profile-${var.environment}"
  role = aws_iam_role.exit_node.name
}

# Security group for exit nodes
resource "aws_security_group" "exit_node" {
  name        = "${var.project_name}-exit-node-sg-${var.environment}"
  description = "Security group for MeshVPN exit nodes"
  vpc_id      = data.aws_vpc.default.id

  # VPN UDP traffic
  ingress {
    from_port   = var.vpn_port
    to_port     = var.vpn_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VPN traffic"
  }

  # SSH (restricted to bastion/management)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.management_cidrs
    description = "SSH access"
  }

  # Allow all outbound traffic (exit nodes need to forward to internet)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "${var.project_name}-exit-node-sg"
  }
}

# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Get latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Launch template for exit nodes
resource "aws_launch_template" "exit_node" {
  name_prefix   = "${var.project_name}-exit-node-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.exit_node.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups            = [aws_security_group.exit_node.id]
  }

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment    = var.environment
    dynamodb_table = aws_dynamodb_table.exit_nodes.name
    s3_bucket      = aws_s3_bucket.logs.id
    vpn_port       = var.vpn_port
    region         = var.primary_region
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-exit-node"
      Role = "exit-node"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for exit nodes
resource "aws_autoscaling_group" "exit_nodes" {
  name                = "${var.project_name}-exit-nodes-${var.environment}"
  desired_capacity    = var.desired_capacity
  max_size            = var.max_capacity
  min_size            = var.min_capacity
  vpc_zone_identifier = data.aws_subnets.default.ids
  health_check_type   = "EC2"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.exit_node.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-exit-node"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Get default subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.project_name}-exit-node-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Exit node CPU utilization is high"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.exit_nodes.name
  }
}

# Auto Scaling policies
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "${var.project_name}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.exit_nodes.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "${var.project_name}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.exit_nodes.name
}

# CloudWatch alarm to trigger scale up
resource "aws_cloudwatch_metric_alarm" "scale_up" {
  alarm_name          = "${var.project_name}-scale-up"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "Scale up when CPU > 70%"
  alarm_actions       = [aws_autoscaling_policy.scale_up.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.exit_nodes.name
  }
}

# CloudWatch alarm to trigger scale down
resource "aws_cloudwatch_metric_alarm" "scale_down" {
  alarm_name          = "${var.project_name}-scale-down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 30
  alarm_description   = "Scale down when CPU < 30%"
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.exit_nodes.name
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "exit_nodes" {
  name              = "/meshvpn/exit-nodes/${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "${var.project_name}-exit-nodes-logs"
  }
}
