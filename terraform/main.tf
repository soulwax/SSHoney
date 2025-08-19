# File: terraform/main.tf

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
  target_group_arns   = [aws_lb_target_group.sshoney_ssh_tg.arn]
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

# Network Load Balancer (for SSH traffic)
resource "aws_lb" "sshoney_nlb" {
  name               = "${var.project_name}-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.sshoney_public[*].id

  enable_deletion_protection = false

  tags = {
    Name        = "${var.project_name}-nlb"
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "sshoney_ssh_tg" {
  name     = "${var.project_name}-ssh-tg"
  port     = 22
  protocol = "TCP"
  vpc_id   = aws_vpc.sshoney_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    port                = "traffic-port"
    protocol            = "TCP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "${var.project_name}-ssh-tg"
    Environment = var.environment
  }
}

resource "aws_lb_listener" "sshoney_ssh_listener" {
  load_balancer_arn = aws_lb.sshoney_nlb.arn
  port              = "22"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sshoney_ssh_tg.arn
  }
}

# Application Load Balancer (for monitoring)
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