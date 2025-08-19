# terraform/main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC and networking
resource "aws_vpc" "sshoney_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "sshoney_igw" {
  vpc_id = aws_vpc.sshoney_vpc.id

  tags = {
    Name        = "${var.project_name}-igw"
    Environment = var.environment
  }
}

resource "aws_subnet" "sshoney_public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.sshoney_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-public-${count.index + 1}"
    Environment = var.environment
  }
}

resource "aws_route_table" "sshoney_public" {
  vpc_id = aws_vpc.sshoney_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sshoney_igw.id
  }

  tags = {
    Name        = "${var.project_name}-public-rt"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "sshoney_public" {
  count = length(aws_subnet.sshoney_public)

  subnet_id      = aws_subnet.sshoney_public[count.index].id
  route_table_id = aws_route_table.sshoney_public.id
}

# Security groups
resource "aws_security_group" "sshoney_sg" {
  name_prefix = "${var.project_name}-"
  vpc_id      = aws_vpc.sshoney_vpc.id

  # SSH access for management
  ingress {
    from_port   = var.ssh_port
    to_port     = var.ssh_port
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
    description = "SSH access for administrators"
  }

  # SSHoney tarpit
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSHoney tarpit"
  }

  # Monitoring
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
    description = "Prometheus"
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
    description = "Grafana"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-sg"
    Environment = var.environment
  }
}

# Key pair
resource "aws_key_pair" "sshoney_key" {
  key_name   = "${var.project_name}-key"
  public_key = var.public_key

  tags = {
    Name        = "${var.project_name}-key"
    Environment = var.environment
  }
}

# Launch template
resource "aws_launch_template" "sshoney_lt" {
  name_prefix   = "${var.project_name}-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.sshoney_key.key_name

  vpc_security_group_ids = [aws_security_group.sshoney_sg.id]

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    ssh_port     = var.ssh_port
    project_name = var.project_name
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "${var.project_name}-instance"
      Environment = var.environment
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "sshoney_asg" {
  name                = "${var.project_name}-asg"
  vpc_zone_identifier = aws_subnet.sshoney_public[*].id
  target_group_arns   = [aws_lb_target_group.sshoney_tg.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.min_instances
  max_size         = var.max_instances
  desired_capacity = var.desired_instances

  launch_template {
    id      = aws_launch_template.sshoney_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-asg"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
}

# Application Load Balancer
resource "aws_lb" "sshoney_alb" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.sshoney_sg.id]
  subnets            = aws_subnet.sshoney_public[*].id

  enable_deletion_protection = false

  tags = {
    Name        = "${var.project_name}-alb"
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "sshoney_tg" {
  name     = "${var.project_name}-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.sshoney_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "${var.project_name}-tg"
    Environment = var.environment
  }
}

resource "aws_lb_listener" "sshoney_listener" {
  load_balancer_arn = aws_lb.sshoney_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sshoney_tg.arn
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "sshoney_logs" {
  name              = "/aws/ec2/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-logs"
    Environment = var.environment
  }
}

# IAM role for EC2 instances
resource "aws_iam_role" "sshoney_role" {
  name = "${var.project_name}-role"

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

  tags = {
    Name        = "${var.project_name}-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "sshoney_policy" {
  name = "${var.project_name}-policy"
  role = aws_iam_role.sshoney_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.sshoney_logs.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "sshoney_profile" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.sshoney_role.name
}

---
# terraform/variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "sshoney"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "min_instances" {
  description = "Minimum number of instances"
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Maximum number of instances"
  type        = number
  default     = 3
}

variable "desired_instances" {
  description = "Desired number of instances"
  type        = number
  default     = 2
}

variable "ssh_port" {
  description = "SSH port for management access"
  type        = number
  default     = 2222
}

variable "admin_cidrs" {
  description = "CIDR blocks allowed for admin access"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production!
}

variable "public_key" {
  description = "Public key for EC2 access"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

---
# terraform/user_data.sh
#!/bin/bash
set -euo pipefail

# Update system
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
    build-essential \
    docker.io \
    docker-compose \
    awscli \
    amazon-cloudwatch-agent \
    fail2ban

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/sshoney/*.log",
                        "log_group_name": "/aws/ec2/${project_name}",
                        "log_stream_name": "{instance_id}/sshoney"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "SSHoney",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_iowait"],
                "metrics_collection_interval": 60
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": ["tcp_established", "tcp_time_wait"],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
systemctl enable amazon-cloudwatch-agent
systemctl start amazon-cloudwatch-agent

# Clone and build SSHoney
cd /opt
git clone https://github.com/your-repo/sshoney.git
cd sshoney

# Build SSHoney
make CFLAGS="-std=c99 -Wall -Wextra -O2 -fstack-protector-strong -fPIE" \
     LDFLAGS="-Wl,-z,relro,-z,now -pie"

# Install SSHoney
cp sshoney /usr/local/bin/
chmod +x /usr/local/bin/sshoney
setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney

# Create sshoney user
useradd -r -s /bin/false -d /var/lib/sshoney sshoney

# Create directories
mkdir -p /etc/sshoney /var/log/sshoney /var/lib/sshoney
chown sshoney:sshoney /var/log/sshoney /var/lib/sshoney

# Configure SSHoney
cat > /etc/sshoney/config << 'EOF'
Port 22
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
BindFamily 0
EOF

# Install systemd service
cp sshoney.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sshoney

# Configure SSH
sed -i 's/^#*Port 22/Port ${ssh_port}/' /etc/ssh/sshd_config
systemctl restart sshd

# Configure fail2ban for SSH protection
cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Start SSHoney
systemctl start sshoney

# Set up monitoring with Docker
docker-compose -f /opt/sshoney/docker-compose.yml up -d prometheus grafana

echo "SSHoney deployment completed successfully!"

---
# terraform/outputs.tf
output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.sshoney_alb.dns_name
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.sshoney_vpc.id
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.sshoney_sg.id
}

output "autoscaling_group_arn" {
  description = "ARN of the Auto Scaling Group"
  value       = aws_autoscaling_group.sshoney_asg.arn
}

output "cloudwatch_log_group" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.sshoney_logs.name
}