# MeshVPN Infrastructure

This directory contains infrastructure-as-code for deploying MeshVPN exit nodes on AWS.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- AWS CLI configured with appropriate credentials
- AWS account with permissions for EC2, DynamoDB, S3, IAM, CloudWatch

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS Cloud                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  us-east-1  │  │  us-west-2  │  │  eu-west-1  │  ...           │
│  │             │  │             │  │             │                 │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │                 │
│  │ │ Exit    │ │  │ │ Exit    │ │  │ │ Exit    │ │                 │
│  │ │ Node(s) │ │  │ │ Node(s) │ │  │ │ Node(s) │ │                 │
│  │ └────┬────┘ │  │ └────┬────┘ │  │ └────┬────┘ │                 │
│  └──────┼──────┘  └──────┼──────┘  └──────┼──────┘                 │
│         │                │                │                         │
│         └───────────┬────┴───────────┬────┘                         │
│                     │                │                               │
│              ┌──────┴──────┐  ┌──────┴──────┐                       │
│              │  DynamoDB   │  │    S3       │                       │
│              │ (Registry)  │  │   (Logs)    │                       │
│              └─────────────┘  └─────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

- **Exit Nodes**: EC2 instances running MeshVPN exit node software
- **Auto Scaling Group**: Manages exit node fleet with auto-scaling
- **DynamoDB**: Stores exit node registry and health status
- **S3**: Stores connection logs and metrics
- **IAM**: Roles and policies for node access to AWS services
- **CloudWatch**: Monitoring, alerting, and log aggregation

## Quick Start

1. **Configure AWS credentials**:
   ```bash
   aws configure
   ```

2. **Copy and edit variables**:
   ```bash
   cd infra/terraform
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your settings
   ```

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Review the plan**:
   ```bash
   terraform plan
   ```

5. **Apply the infrastructure**:
   ```bash
   terraform apply
   ```

## Configuration

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_name` | Prefix for all resources | `meshvpn` |
| `environment` | Environment name (prod/staging/dev) | `prod` |
| `primary_region` | Primary AWS region | `us-east-1` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `instance_type` | EC2 instance type | `t3.medium` |
| `desired_capacity` | Desired number of nodes | `2` |
| `min_capacity` | Minimum nodes | `1` |
| `max_capacity` | Maximum nodes | `10` |
| `vpn_port` | UDP port for VPN | `51820` |
| `management_cidrs` | CIDR blocks for SSH | `["10.0.0.0/8"]` |

## Multi-Region Deployment

To deploy in multiple regions, use the provider aliases defined in `main.tf`:

```hcl
# Create a module for each region
module "exit_nodes_us_west" {
  source = "./modules/exit-node"
  providers = {
    aws = aws.us_west_2
  }
  # ... configuration
}
```

## Outputs

After applying, you'll get these outputs:

- `dynamodb_table_name`: DynamoDB table for node registry
- `s3_bucket_name`: S3 bucket for logs
- `security_group_id`: Security group ID for nodes
- `autoscaling_group_name`: ASG name for monitoring

## Operations

### Scaling

```bash
# Manual scaling
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name meshvpn-exit-nodes-prod \
  --desired-capacity 5

# View current instances
aws autoscaling describe-auto-scaling-instances \
  --query 'AutoScalingInstances[?AutoScalingGroupName==`meshvpn-exit-nodes-prod`]'
```

### Viewing Logs

```bash
# CloudWatch Logs
aws logs tail /meshvpn/exit-nodes/prod --follow

# S3 Logs
aws s3 ls s3://meshvpn-logs-prod-xxxx/
```

### Monitoring

CloudWatch dashboard and alarms are automatically created. Access via AWS Console:
- CloudWatch > Dashboards > MeshVPN
- CloudWatch > Alarms

## Destroying Infrastructure

⚠️ **Warning**: This will delete all exit nodes and data!

```bash
terraform destroy
```

## Security Considerations

1. **SSH Access**: Limited to `management_cidrs` - configure with your bastion/VPN IPs
2. **IAM**: Follows least-privilege principle
3. **IMDSv2**: Enforced for instance metadata
4. **S3**: Server-side encryption enabled, public access blocked
5. **DynamoDB**: Point-in-time recovery enabled

## Cost Estimation

Approximate monthly costs (us-east-1):
- t3.medium instances: ~$30/instance
- DynamoDB: ~$25-50 (PAY_PER_REQUEST)
- S3: ~$5-20 (depends on log volume)
- CloudWatch: ~$5-10
- Data transfer: Variable (main cost for VPN)

**Total**: ~$100-200/region for basic setup

## Troubleshooting

### Node not registering in DynamoDB
1. Check CloudWatch logs for errors
2. Verify IAM role has DynamoDB permissions
3. Check instance can reach DynamoDB endpoint

### High CPU/Memory
1. Check connection count
2. Consider scaling up instance type
3. Review bandwidth limits

### SSH access issues
1. Verify `management_cidrs` includes your IP
2. Check security group rules
3. Ensure SSH key is configured (if using)

## Support

For issues or questions, please open an issue in the repository.
