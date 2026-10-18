locals {
  name = "cloudsentinel-p${var.project_id}-${var.environment}"
  tags = {
    Project     = "CloudSentinel"
    ProjectId   = tostring(var.project_id)
    Environment = var.environment
    Module      = "8-network"
    ManagedBy   = "Terraform"
  }
}
resource "aws_vpc" "this" {
  cidr_block                       = var.vpc_cidr
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = false
  tags                             = merge(local.tags, { Name = "${local.name}-vpc" })
}
resource "aws_subnet" "public" {
  vpc_id                          = aws_vpc.this.id
  cidr_block                      = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone               = var.availability_zone
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  tags                            = merge(local.tags, { Name = "${local.name}-public", NetworkTier = "public" })
}
resource "aws_subnet" "private" {
  vpc_id                          = aws_vpc.this.id
  cidr_block                      = cidrsubnet(var.vpc_cidr, 8, 2)
  availability_zone               = var.availability_zone
  map_public_ip_on_launch         = false
  assign_ipv6_address_on_creation = false
  tags                            = merge(local.tags, { Name = "${local.name}-private", NetworkTier = "private" })
}
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${local.name}-public-routes" })
}
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  # Only the AWS-managed local VPC route. No NAT, IGW or IPv6 default route.
  tags = merge(local.tags, { Name = "${local.name}-private-routes" })
}
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}
# Explicit empty lists remove AWS's implicit allow-all SG egress. No workloads
# or traffic permissions are provisioned in this networking phase.
resource "aws_security_group" "public" {
  name_prefix            = "${local.name}-public-"
  description            = "Deny all ingress and egress pending separate workload approval"
  vpc_id                 = aws_vpc.this.id
  ingress                = []
  egress                 = []
  revoke_rules_on_delete = true
  tags                   = merge(local.tags, { Name = "${local.name}-public-sg" })
}
resource "aws_security_group" "private" {
  name_prefix            = "${local.name}-private-"
  description            = "Deny all ingress and egress for isolated private subnet workloads"
  vpc_id                 = aws_vpc.this.id
  ingress                = []
  egress                 = []
  revoke_rules_on_delete = true
  tags                   = merge(local.tags, { Name = "${local.name}-private-sg" })
}
# Manage only the new VPC's default SG, never the account's existing default VPC.
resource "aws_default_security_group" "this" {
  vpc_id  = aws_vpc.this.id
  ingress = []
  egress  = []
  tags    = merge(local.tags, { Name = "${local.name}-default-deny" })
}
# Log delivery storage/policy is provisioned separately by its authorized owner.
# The network stack does not create buckets, roles or modify bucket policies.
resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = var.flow_log_destination_arn
  max_aggregation_interval = 60
  tags                     = merge(local.tags, { Name = "${local.name}-flow-logs" })
}
