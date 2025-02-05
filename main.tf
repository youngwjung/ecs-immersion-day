# 해당 모듈 실행에 필요한 제공자 설정
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.84.0"
    }
  }
}

# 현재 설정된 AWS 리전에 있는 가용영역 정보 불러오기
data "aws_availability_zones" "azs" {}

# VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.17.0"

  name = "ecs-vpc"
  cidr = "10.0.0.0/16"

  azs             = data.aws_availability_zones.azs.names
  public_subnets  = [for idx, _ in data.aws_availability_zones.azs.names : cidrsubnet("10.0.0.0/16", 8, idx)]
  private_subnets = [for idx, _ in data.aws_availability_zones.azs.names : cidrsubnet("10.0.0.0/16", 8, idx + 10)]

  enable_nat_gateway = true
  single_nat_gateway = true
}

# Cloud9
resource "aws_cloud9_environment_ec2" "this" {
  instance_type               = "t3.medium"
  name                        = "ecs"
  image_id                    = "amazonlinux-2023-x86_64"
  automatic_stop_time_minutes = 60
  connection_type             = "CONNECT_SSH"
  subnet_id                   = module.vpc.public_subnets[0]
}

# ECS Instance Role
module "ecs_instance_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.52.2"

  role_name               = "ecsInstanceRole"
  create_role             = true
  create_instance_profile = true
  role_requires_mfa       = false
  trusted_role_services   = ["ec2.amazonaws.com"]
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
  ]
}

# ECS 인스턴스에 부여할 보안그룹
module "ecs_instance_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.3.0"

  name            = "ecs-instance-sg"
  use_name_prefix = false
  description     = "ecs instance security group"
  vpc_id          = module.vpc.vpc_id

  # 모든 아웃바운드 허용
  egress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules       = ["all-all"]
}

# CodeCommit
resource "aws_cloudformation_stack" "codecommit" {
  name = "codecommit"

  template_body = jsonencode({
    Resources = {
      codeCommit = {
        Type = "AWS::CodeCommit::Repository"
        Properties = {
          RepositoryName = "backend"
          Code = {
            S3 = {
              Bucket = "youngwjung"
              Key    = "immersion-day/spring-boot-demo-main.zip"
            }
          }
        }
      }
    }
  })
}

# ECR
resource "aws_ecr_repository" "backend" {
  name         = "backend"
  force_delete = true
}

# ECS Task Execution Role
module "ecs_task_execution_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.52.2"

  role_name               = "ecsTaskExecutionRole"
  create_role             = true
  create_instance_profile = true
  role_requires_mfa       = false
  trusted_role_services   = ["ecs-tasks.amazonaws.com"]
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
  ]
}

# ECS Task에 부여할 보안그룹
module "backend_task_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.3.0"

  name            = "backend-task-sg"
  use_name_prefix = false
  description     = "backend task security group"
  vpc_id          = module.vpc.vpc_id

  ingress_with_source_security_group_id = [
    {
      rule                     = "http-8080-tcp"
      source_security_group_id = module.backend_alb_sg.security_group_id
    }
  ]

  # 모든 아웃바운드 허용
  egress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules       = ["all-all"]
}

# ALB에 부여할 보안그룹
module "backend_alb_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.3.0"

  name            = "my-backend-alb-sg"
  use_name_prefix = false
  description     = "my backend alb security group"
  vpc_id          = module.vpc.vpc_id

  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp"]

  # 모든 아웃바운드 허용
  egress_cidr_blocks = ["0.0.0.0/0"]
  egress_rules       = ["all-all"]
}

# 백엔드 ALB
module "backend_alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "9.13.0"

  name = "my-backend-alb"

  vpc_id                     = module.vpc.vpc_id
  subnets                    = module.vpc.public_subnets
  create_security_group      = false
  security_groups            = [module.backend_alb_sg.security_group_id]
  enable_deletion_protection = false

  listeners = {
    http = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "my-backend-task"
      }
    }
  }

  target_groups = {
    my-backend-task = {
      name                 = "my-backend-task"
      protocol             = "HTTP"
      port                 = 8080
      target_type          = "ip"
      deregistration_delay = 30

      health_check = {
        path = "/api/healthz"
      }

      create_attachment = false
    }
  }
}
