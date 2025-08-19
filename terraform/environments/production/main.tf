# File: terraform/environments/production/main.tf

terraform {
  required_version = ">= 1.0"
  
  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "sshoney/production/terraform.tfstate"
    region = "us-west-2"
    
    # Enable state locking
    dynamodb_table = "terraform-state-locks"
    encrypt        = true
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "production"
      ManagedBy   = "Terraform"
      Owner       = "Security Team"
    }
  }
}

module "sshoney" {
  source = "../../modules/sshoney"
  
  project_name      = var.project_name
  environment       = "production"
  vpc_id           = module.vpc.vpc_id
  subnet_ids       = module.vpc.public_subnet_ids
  ssh_port         = var.ssh_port
  admin_cidrs      = var.admin_cidrs
  instance_type    = var.instance_type
  min_instances    = var.min_instances
  max_instances    = var.max_instances
  desired_instances = var.desired_instances
  public_key       = var.public_key
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${var.project_name}-vpc"
  cidr = var.vpc_cidr
  
  azs             = data.aws_availability_zones.available.names
  public_subnets  = var.public_subnet_cidrs
  
  enable_nat_gateway = false
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true
  
  tags = {
    Environment = "production"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}