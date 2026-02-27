---
title: "VPC peering route table with unrestricted CIDR"
group_id: "Terraform / AWS"
meta:
  name: "aws/vpc_peering_route_table_with_unrestricted_cidr"
  id: "b3a41501-f712-4c4f-81e5-db9a7dc0e34e"
  display_name: "VPC peering route table with unrestricted CIDR"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `b3a41501-f712-4c4f-81e5-db9a7dc0e34e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route)

### Description

VPC Peering Route Tables with unrestricted CIDR blocks (`0.0.0.0/0`) create a significant security vulnerability by allowing all IP addresses to route through the VPC peering connection. This configuration effectively bypasses network isolation between VPCs and exposes your resources to potential unauthorized access from any IP address that can reach the peering connection.

Instead of using unrestricted CIDR blocks, you should always limit the route to the specific IP range of the peered VPC or a minimum required subset. For example, use `cidr_block = "10.0.0.0/8"` or the exact VPC CIDR such as `cidr_block = aws_vpc.vpc2.cidr_block`, instead of `cidr_block = "0.0.0.0/0"`.

## Compliant Code Examples
```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.55.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable vpc_1_cidr_block {
  type        = string
  default     = "10.0.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_2_cidr_block {
  type        = string
  default     = "10.2.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_cidr_public_block {
  type        = string
  default     = "10.0.1.0/24"
  description = "public CIDR block"
}

variable vpc_cidr_private_block {
  type        = string
  default     = "10.0.2.0/24"
  description = "private CIDR block"
}

resource "aws_vpc" "vpc1" {
  cidr_block = var.vpc_1_cidr_block

  tags = {
    Name = "tf-test-vpc-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_public_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "public-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_private_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "private-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_vpc" "vpc2" {
  cidr_block = var.vpc_2_cidr_block

  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id                  = aws_vpc.vpc1.id

  tags                    = {
    Name                  = "igw"
    Project               = "CIS Certification"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id          = aws_eip.nat.id
  subnet_id              = aws_subnet.public.*.id[0]

  tags                   = {
    Name                 = "nat"
    Project              = "CIS Certification"
  }

  depends_on             = [aws_internet_gateway.igw]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc_peering_connection" "my_peering" {
  peer_owner_id = data.aws_caller_identity.current.account_id
  peer_vpc_id   = aws_vpc.vpc1.id
  vpc_id        = aws_vpc.vpc2.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between vpc1 and vpc2"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route = [

    {
      cidr_block                 = "10.0.0.0/8"
      vpc_peering_connection_id  = aws_vpc_peering_connection.my_peering.id
      gateway_id                 = ""
      instance_id                = ""
      ipv6_cidr_block            = ""
      egress_only_gateway_id     = ""
      nat_gateway_id             = ""
      network_interface_id       = ""
      transit_gateway_id         = ""
      carrier_gateway_id         = ""
      destination_prefix_list_id = ""
      local_gateway_id           = ""
      vpc_endpoint_id            = ""

    }
  ]
  

  tags = {
    Name = "public_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route {
    cidr_block                  = aws_vpc.vpc2.cidr_block
    vpc_peering_connection_id   = aws_vpc_peering_connection.my_peering.id
  }

  tags = {
    Name = "private_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table_association" "private_route_table_association" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_route_table.id
}

```

```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "<= 3.49.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable vpc_1_cidr_block {
  type        = string
  default     = "10.0.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_2_cidr_block {
  type        = string
  default     = "10.2.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_cidr_public_block {
  type        = string
  default     = "10.0.1.0/24"
  description = "public CIDR block"
}

variable vpc_cidr_private_block {
  type        = string
  default     = "10.0.2.0/24"
  description = "private CIDR block"
}

resource "aws_vpc" "vpc1" {
  cidr_block = var.vpc_1_cidr_block
  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_public_block
  availability_zone = "us-east-1a"


  tags = {
    Name    = "public-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_private_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "private-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_vpc" "vpc2" {
  cidr_block = var.vpc_2_cidr_block
  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id                  = aws_vpc.vpc1.id

  tags                    = {
    Name                  = "igw"
    Project               = "CIS Certification"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id          = aws_eip.nat.id
  subnet_id              = aws_subnet.public.*.id[0]

  tags                   = {
    Name                 = "nat"
    Project              = "CIS Certification"
  }

  depends_on             = [aws_internet_gateway.igw]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc_peering_connection" "my_peering" {
  peer_owner_id = data.aws_caller_identity.current.account_id
  peer_vpc_id   = aws_vpc.vpc1.id
  vpc_id        = aws_vpc.vpc2.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between vpc1 and vpc2"
    Project = "CIS Certification"
  }
}


resource "aws_route_table" "public_route_table2" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "public-route-table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Project = "CIS Certification"
  }
}

resource "aws_route" "private_route2" {
  route_table_id            = aws_route_table.public_route_table2.id
  destination_cidr_block    = "10.0.0.0/8"
  vpc_peering_connection_id = aws_vpc_peering_connection.my_peering.id
  depends_on                = [aws_route_table.public_route_table2]
}

resource "aws_route_table_association" "private_route_table_association" {
  subnet_id      = aws_subnet.private.*.id[0]
  route_table_id = aws_route_table.private_route_table.id
}

```

```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "<= 3.49.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable vpc_1_cidr_block {
  type        = string
  default     = "10.0.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_2_cidr_block {
  type        = string
  default     = "10.2.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_cidr_public_block {
  type        = string
  default     = "10.0.1.0/24"
  description = "public CIDR block"
}

variable vpc_cidr_private_block {
  type        = string
  default     = "10.0.2.0/24"
  description = "private CIDR block"
}

resource "aws_vpc" "vpc1" {
  cidr_block = var.vpc_1_cidr_block

  tags = {
    Name = "tf-test-vpc-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_public_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "public-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_private_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "private-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_vpc" "vpc2" {
  cidr_block = var.vpc_2_cidr_block

  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id                  = aws_vpc.vpc1.id

  tags                    = {
    Name                  = "igw"
    Project               = "CIS Certification"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id          = aws_eip.nat.id
  subnet_id              = aws_subnet.public.*.id[0]

  tags                   = {
    Name                 = "nat"
    Project              = "CIS Certification"
  }

  depends_on             = [aws_internet_gateway.igw]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc_peering_connection" "my_peering" {
  peer_owner_id = data.aws_caller_identity.current.account_id
  peer_vpc_id   = aws_vpc.vpc1.id
  vpc_id        = aws_vpc.vpc2.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between vpc1 and vpc2"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route {
    cidr_block                  = "10.0.0.0/8"
    vpc_peering_connection_id   = aws_vpc_peering_connection.my_peering.id
  }

  tags = {
    Name = "public_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route {
    cidr_block                  = aws_vpc.vpc2.cidr_block
    vpc_peering_connection_id   = aws_vpc_peering_connection.my_peering.id
  }

  tags = {
    Name = "private_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table_association" "private_route_table_association" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_route_table.id
}

```
## Non-Compliant Code Examples
```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "<= 3.49.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable vpc_1_cidr_block {
  type        = string
  default     = "10.0.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_2_cidr_block {
  type        = string
  default     = "10.2.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_cidr_public_block {
  type        = string
  default     = "10.0.1.0/24"
  description = "public CIDR block"
}

variable vpc_cidr_private_block {
  type        = string
  default     = "10.0.2.0/24"
  description = "private CIDR block"
}

resource "aws_vpc" "vpc1" {
  cidr_block = var.vpc_1_cidr_block
  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_public_block
  availability_zone = "us-east-1a"


  tags = {
    Name    = "public-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_private_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "private-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_vpc" "vpc2" {
  cidr_block = var.vpc_2_cidr_block
  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id                  = aws_vpc.vpc1.id

  tags                    = {
    Name                  = "igw"
    Project               = "CIS Certification"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id          = aws_eip.nat.id
  subnet_id              = aws_subnet.public.*.id[0]

  tags                   = {
    Name                 = "nat"
    Project              = "CIS Certification"
  }

  depends_on             = [aws_internet_gateway.igw]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc_peering_connection" "my_peering" {
  peer_owner_id = data.aws_caller_identity.current.account_id
  peer_vpc_id   = aws_vpc.vpc1.id
  vpc_id        = aws_vpc.vpc2.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between vpc1 and vpc2"
    Project = "CIS Certification"
  }
}


resource "aws_route_table" "public_route_table9" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "public-route-table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Project = "CIS Certification"
  }
}

resource "aws_route" "private_route2" {
  route_table_id            = aws_route_table.public_route_table9.id
  destination_cidr_block    = "0.0.0.0/0"
  vpc_peering_connection_id = aws_vpc_peering_connection.my_peering.id
  depends_on                = [aws_route_table.public_route_table9]
}

resource "aws_route_table_association" "private_route_table_association" {
  subnet_id      = aws_subnet.private.*.id[0]
  route_table_id = aws_route_table.private_route_table.id
}

```

```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.55.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable vpc_1_cidr_block {
  type        = string
  default     = "10.0.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_2_cidr_block {
  type        = string
  default     = "10.2.0.0/16"
  description = "vpc default CIDR block"
}

variable vpc_cidr_public_block {
  type        = string
  default     = "10.0.1.0/24"
  description = "public CIDR block"
}

variable vpc_cidr_private_block {
  type        = string
  default     = "10.0.2.0/24"
  description = "private CIDR block"
}

resource "aws_vpc" "vpc1" {
  cidr_block = var.vpc_1_cidr_block

  tags = {
    Name = "tf-test-vpc-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_public_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "public-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = var.vpc_cidr_private_block
  availability_zone = "us-east-1a"

  tags = {
    Name    = "private-subnet-1"
    Project = "CIS Certification"
  }
}

resource "aws_vpc" "vpc2" {
  cidr_block = var.vpc_2_cidr_block

  tags = {
    Name = "tf-test-vpc-2"
    Project = "CIS Certification"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id                  = aws_vpc.vpc1.id

  tags                    = {
    Name                  = "igw"
    Project               = "CIS Certification"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id          = aws_eip.nat.id
  subnet_id              = aws_subnet.public.*.id[0]

  tags                   = {
    Name                 = "nat"
    Project              = "CIS Certification"
  }

  depends_on             = [aws_internet_gateway.igw]
}

data "aws_caller_identity" "current" {}

resource "aws_vpc_peering_connection" "my_peering" {
  peer_owner_id = data.aws_caller_identity.current.account_id
  peer_vpc_id   = aws_vpc.vpc1.id
  vpc_id        = aws_vpc.vpc2.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between vpc1 and vpc2"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route = [

    {
      cidr_block                 = "0.0.0.0/0"
      vpc_peering_connection_id  = aws_vpc_peering_connection.my_peering.id
      gateway_id                 = ""
      instance_id                = ""
      ipv6_cidr_block            = ""
      egress_only_gateway_id     = ""
      nat_gateway_id             = ""
      network_interface_id       = ""
      transit_gateway_id         = ""
      carrier_gateway_id         = ""
      destination_prefix_list_id = ""
      local_gateway_id           = ""
      vpc_endpoint_id            = ""

    }
  ]
  

  tags = {
    Name = "public_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc1.id

  route {
    cidr_block                  = aws_vpc.vpc2.cidr_block
    vpc_peering_connection_id   = aws_vpc_peering_connection.my_peering.id
  }

  tags = {
    Name = "private_route_table"
    Project = "CIS Certification"
  }
}

resource "aws_route_table_association" "private_route_table_association" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_route_table.id
}

```

```terraform
resource "aws_route_table" "art_nat_gw_out" {
  vpc_id = aws_vpc.av_xxx.id

  route {
    nat_gateway_id = aws_nat_gateway.ngw01.id
    cidr_block     = "10.0.0.0/24"
  }

  route {
    vpc_peering_connection_id = aws_vpc_peering_connection.avpv.id
    cidr_block                = "0.0.0.0/0"
  }
}

```