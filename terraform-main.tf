
#========================================================================================================
#==============================================TERRAFORM SCRIPTS=========================================
#========================================================================================================





#========================================================================================================
#====================================AUTHENTICATION======================================================
#========================================================================================================

terraform {
  required_version = "~> 1.3.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  profile = "emcode"
  region  = "us-east-1"
  access_key= ${{ secrets.access_key }}
  secret_key= ${{ secrets.secret_key }}
}

#=======================================================================================================
#==================================CREATION OF ORGANISATION=============================================
#=======================================================================================================


resource "aws_organizations_organization" "organization" {



 aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
  ]

  feature_set = "ALL"


 enabled_policy_types = [
    "TAG_POLICY",
    "SERVICE_CONTROL_POLICY"
  ]



}
#========================================================================================================
#====================================CREATION OF ORGANISATION UNIT=======================================
#========================================================================================================

#Creating main organisation unit

resource "aws_organizations_organizational_unit" "Emcode" {
  name      = var.name
  parent_id = aws_organizations_organization.organization.roots[0].id
}

#========================================================================================================

#Creating sub organisation unit

resource "aws_organizations_organizational_unit" "prod" {
  name      = var.prod_name
  parent_id = aws_organizations_organizational_unit.Emcode.id

  depends_on = [
    aws_organizations_organizational_unit.Emcode
  ]
}


#Creating sub organisation unit

resource "aws_organizations_organizational_unit" "qa" {
  name      = var.qa_name
  parent_id = aws_organizations_organizational_unit.Emcode.id

  depends_on = [
    aws_organizations_organizational_unit.Emcode
  ]
}

#========================================================================================================

#Creating a master account with requirede permissions in the sub OU

resource "aws_organizations_account" "master" {
# A friendly name for the member account
  name  = "Sonu"
  email = "Sonu@email.com"

  tags = {
    Name  = "Sonu"
    Owner = "EMCODE"

  }

  parent_id = aws_organizations_organizational_unit.prod.id
}

#Creating a master account with requirede permissions in the sub OU

resource "aws_organizations_account" "master" {
# A friendly name for the member account
  name  = "Reena"
  email = "reena@email.com"

  tags = {
    Name  = "Reena"
    Owner = "EMCODE"

  }

  parent_id = aws_organizations_organizational_unit.QA.id
}



#========================================================================================================
#================================================CREATION OF ADMIN GROUPS================================
#========================================================================================================

#Creating iam group for administrator

resource "aws_iam_group" "administrators" {
  name = var.iam_group_administrators_name
  path = "/"
}


#========================================================================================================

#Creating iam policy and attaching it to the iam group

data "aws_iam_policy" "administrator_access" {
  name = "AdministratorAccess"
}


resource "aws_iam_group_policy_attachment" "administrators" {
  group      = aws_iam_group.administrators.name
  policy_arn = data.aws_iam_policy.administrator_access.arn
}

#========================================================================================================

#Creating a user in administrator and attaching to the iam group

resource "aws_iam_user" "administrator" {
  name = var.iam_user_administrators_name
}

resource "aws_iam_user_group_membership" "devstream" {
  user   = aws_iam_user.administrator.name
  groups = [aws_iam_group.administrators.name]
}

#Giving credential permissions to users
import {
  to = aws_iam_policy.administrator
  id = "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials"
}

#========================================================================================================
#==============================================CREATION OF BUDGET ALARM==================================
#========================================================================================================


#Creating budget alarms and sending alert to required budget_alert_emails

locals {
  budget_alert_emails = [
    "nicola@emcode.com",
    "jane@emcode.com"
  ]
}
#========================================================================================================

#Creating daily_budget

resource "aws_budgets_budget" "daily_budget" {
  name              = "daily-budget"
  budget_type       = "COST"
  limit_amount      = "10.0"
  limit_unit        = "USD"
  time_period_start = "2021-01-01_00:00"
  time_period_end   = "2085-01-01_00:00"
  time_unit         = "DAILY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = local.budget_alert_emails
  }
}

#========================================================================================================

#Creating monthly budget

resource "aws_budgets_budget" "monthly_budget" {
  name              = "monthly-budget"
  budget_type       = "COST"
  limit_amount      = "50.0"
  limit_unit        = "USD"
  time_period_end   = "2085-01-01_00:00"
  time_period_start = "2021-01-01_00:00"
  time_unit         = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = local.budget_alert_emails
  }
}



#========================================================================================================
#============================================CREATION OF DEVELOPER GROUPS================================
#========================================================================================================


#Creating a user

resource "aws_iam_user" "achintha" {
  name = var.iam_user_developer_name

  tags = {
    creator = "achintha"
  }
}

#========================================================================================================

#Creating access key and secret key

resource "aws_iam_access_key" "achintha_access_key" {
  user = aws_iam_user.achintha.name
}

output "access_key_id" {
  value = aws_iam_access_key.achintha_access_key.id
  sensitive = true
}

output "secret_access_key" {
  value = aws_iam_access_key.achintha_access_key.secret
  sensitive = true
}

locals {
  achintha_keys_csv = "access_key,secret_key\n${aws_iam_access_key.achintha_access_key.id},${aws_iam_access_key.achintha_access_key.secret}"
}

#========================================================================================================
#Downloading the secret key as csv file

resource "local_file" "achintha_keys" {
  content  = local.achintha_keys_csv
  filename = "achintha-keys.csv"
}



#========================================================================================================
#Creating iam group for developers

resource "aws_iam_group" "terraform-developers" {
  name = var.iam_group_developer_name
}
#Attaching the user to the iam group

resource "aws_iam_group_membership" "achintha_membership" {
  name = aws_iam_user.achintha.name
  users = [aws_iam_user.achintha.name]
  group = aws_iam_group.terraform-developers.name
}

#========================================================================================================

#Giving required permissions to the developer group

#rds full

data "aws_iam_policy" "rds_full_access" {
  arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

#ec2 start and stop permisisons

data "aws_iam_policy_document" "ec2_instance_actions" {
  statement {
    actions = [
      "ec2:StartInstances",
      "ec2:StopInstances",
    ]

    resources = [
      "arn:aws:ec2:*:*:instance/*",
    ]
  }
}




#Billing access

resource "aws_iam_policy" "billing_view_policy" {
  description = "An IAM policy that allows IAM users to view the following Billing and Cost Management console pages, without giving them access to the Account Settings or Reports console pages"
  policy = jsonencode(
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "aws-portal:ViewBilling"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
)

}

#========================================================================================================

#Attaching the policies

resource "aws_iam_policy" "ec2_instance_actions" {
  name        = "ec2_instance_actions"
  policy      = data.aws_iam_policy_document.ec2_instance_actions.json
}

resource "aws_iam_group_policy_attachment" "terraform-developers_rds_full_access" {
  policy_arn = data.aws_iam_policy.rds_full_access.arn
  group      = aws_iam_group.terraform-developers.name
}

resource "aws_iam_group_policy_attachment" "developers_ec2_instance_actions" {
  policy_arn = aws_iam_policy.ec2_instance_actions.arn
  group      = aws_iam_group.terraform-developers.name
}

resource "aws_iam_group_policy_attachment" "developres_billing_view_access" {
  policy_arn = aws_iam_policy.billing_view_policy.arn
  group      = aws_iam_group.terraform-developers.name
}



#========================================================================================================
#================================================CREATION QA GROUP================================
#========================================================================================================


#Creating a user

resource "aws_iam_user" "reeta" {
  name = "reeta"

  tags = {
    creator = "reeta"
  }
}

#========================================================================================================

#Creating access key and secret key

resource "aws_iam_access_key" "reeta_access_key" {
  user = aws_iam_user.reeta.name
}

output "access_key_id" {
  value = aws_iam_access_key.reeta_access_key.id
  sensitive = true
}

output "secret_access_key" {
  value = aws_iam_access_key.reeta_access_key.secret
  sensitive = true
}

locals {
  reeta_keys_csv = "access_key,secret_key\n${aws_iam_access_key.reeta_access_key.id},${aws_iam_access_key.reeta_access_key.secret}"
}

#========================================================================================================
#Downloading the secret key as csv file

resource "local_file" "reeta_keys" {
  content  = local.reeta_keys_csv
  filename = "reeta-keys.csv"
}



#========================================================================================================
#Creating iam group for developers

resource "aws_iam_group" "emcode-qa" {
  name = "emcode-qa"
}

#Attaching the user to the iam group

resource "aws_iam_group_membership" "reeta_membership" {
  name = aws_iam_user.reeta.name
  users = [aws_iam_user.reeta.name]
  group = aws_iam_group.emcode-qa.name
}

resource "aws_iam_group_policy_attachment" "qa_ec2_instance_cloudwatch" {
  count = length(local.role_policy_arns)
  policy_arn = element(local.role_policy_arns, count.index)
  group      = aws_iam_group.emcode-qa.name

}


#=========================================================================================================
#================CREATION OF CLOUDWATCH, PUSH EC2 LOGS TO CLOUD WATCH AND CREATION OF WEB SERVER==========
#=========================================================================================================




resource "aws_instance" "this" {
  ami                  = "ami-03e0b06f01d45a4eb"
  instance_type        = "t3.micro"
  key_name             = var.key_name
  vpc_security_group_ids = [aws_security_group.nginx_demo.id]
  iam_instance_profile = aws_iam_instance_profile.this.name

   provisioner "file" {
    source      = "/home/ec2-user/task/test5/sample/cw_agent_config.json"
    destination = "/tmp/config.json"

   connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ec2-user"
    password = "itsasecret"
    private_key = file ("/home/ec2-user/task/test5/sample/${var.key_name}.pem")
  }
}





  user_data            = <<-EOF
                    #!/bin/bash
                    echo "Hello, World!" > hello.txt
                    set -e
                    exec > >(tee /var/log/user-data.log|logger -t user-data-extra -s 2>/dev/console) 2>&1
                    yum update -y
                    yum upgrade -y
                    wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
                    rpm -U ./amazon-cloudwatch-agent.rpm
                    cp -r /tmp/config.json /opt/aws/amazon-cloudwatch-agent/bin/config.json
                    amazon-linux-extras install collectd
                    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                    -a fetch-config \
                    -m ec2 \
                    -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
                    amazon-linux-extras install nginx1
                    service nginx start

                    echo 'Done initialization'
                  EOF


  tags                 = { Name = "EC2-with-cw-agent" }
}

#resource "aws_ssm_parameter" "cw_agent" {
#  description = "Cloudwatch agent config to configure custom log"
#  name        = "/cloudwatch-agent/config"
#  type        = "String"
#  value       = "${file("/home/ec2-user/task/test5/sample/cw_agent_config.json")}"

#}
#========================================================================================================

#===================================================================================================================


#Creation of instance profile - instance profile.tf

locals {
  role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
    "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
  ]
}

resource "aws_iam_instance_profile" "this" {
  name = "EC2-Profile"
  role = aws_iam_role.this.name
}

resource "aws_iam_role_policy_attachment" "this" {
  count = length(local.role_policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = element(local.role_policy_arns, count.index)
}

resource "aws_iam_role_policy" "this" {
  name = "EC2-Inline-Policy"
  role = aws_iam_role.this.id
  policy = jsonencode(

   {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
        "ssm:GetParameter"
    ],
      "Resource" : "*"
  }
 ]
 }

  )
}

resource "aws_iam_role" "this" {
  name = "EC2-Role"
  path = "/"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "ec2.amazonaws.com"
          },
          "Effect" : "Allow"
        }
      ]
    }
  )
}



#========================================================================================================
#=========================CREATION OF EC2 INSTANCE WITH AUTOSCALING GROUP================================
#========================================================================================================





#Creating of vpc

resource "aws_vpc" "my_vpc" {
  name      = var.vpc_name
  cidr_block       = var.vpc_address_space_range
  enable_dns_hostnames = true


}

#========================================================================================================

#Creating subnet

resource "aws_subnet" "public_us_east_1a" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet1_address_prefixes_range
  availability_zone = "us-east-1a"

  tags = {
    Name = "Public Subnet us-east-1a"
  }
}

resource "aws_subnet" "public_us_east_1b" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = var.subnet2_address_prefixes_range
  availability_zone = "us-east-1b"

  tags = {
    Name = "Public Subnet us-east-1b"
  }
}

#========================================================================================================

#Creating an igw

resource "aws_internet_gateway" "my_vpc_igw" {
  name = var.internet_gateway_name
  vpc_id = aws_vpc.my_vpc.id

 
}

#========================================================================================================

#Creating route Table

resource "aws_route_table" "my_vpc_public" {
    name   = var.route_table_name
    vpc_id = aws_vpc.my_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.my_vpc_igw.id
    }

    
}

#========================================================================================================

# associating it to the Subnets

resource "aws_route_table_association" "my_vpc_us_east_2a_public" {
    subnet_id = aws_subnet.public_us_east_1a.id
    route_table_id = aws_route_table.my_vpc_public.id
}

resource "aws_route_table_association" "my_vpc_us_east_2b_public" {
    subnet_id = aws_subnet.public_us_east_1b.id
    route_table_id = aws_route_table.my_vpc_public.id
}

#========================================================================================================

# Creation of security group

resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP inbound connections"
  vpc_id = aws_vpc.my_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Allow HTTP Security Group"
  }
}

#========================================================================================================

#Creation of role

resource "aws_iam_role" "role" {
  name = "test_role"
  path = "/"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}
#========================================================================================================


#========================================================================================================

#Creating the launch instance

resource "aws_launch_configuration" "web" {
  image_id = "ami-08a52ddb321b32a8c"
#  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.this.id

}



#========================================================================================================
#============================================CREATION OF AUTOSCALING GROUP===============================
#========================================================================================================

#Creating an autoscaling group

resource "aws_autoscaling_group" "web" {
  name = var.autoscaling_group_name

  min_size             = 1
  desired_capacity     = 2
  max_size             = 4

 launch_configuration = aws_launch_configuration.web.name

  vpc_zone_identifier  = [
    aws_subnet.public_us_east_1a.id,
    aws_subnet.public_us_east_1b.id
  ]

  # Required to redeploy without an outage.
  lifecycle {
    create_before_destroy = true
  }




}

#========================================================================================================

#Attaching it to the autoscaling group

resource "aws_autoscaling_policy" "web_policy_up" {
  name = "web_policy_up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.web.name
}

#========================================================================================================
#================================================CREATION OF MFA=========================================
#========================================================================================================

#Creation of MFA


data "aws_iam_policy_document" "enforce_mfa" {
  statement {
    sid    = "DenyAllExceptListedIfNoMFA"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken"
    ]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false", ]
    }
  }
}
  
resource "aws_iam_policy" "enforce_mfa" {
  name        = "enforce-to-use-mfa"
  path        = "/"
  description = "Policy to allow MFA management"
  policy      = data.aws_iam_policy_document.enforce_mfa.json
}

resource "aws_iam_group_policy_attachment" "enforce_mfa" {
  group      = aws_iam_group.administrators.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}
#======================================================================================================

#Creating password for the instance

password_policy.tf
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 10
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 3
}
#========================================================================================================
#==============================================CREATION OF RDS===========================================
#========================================================================================================





#Creating iam role for the rds
resource "aws_iam_role" "rds_auth_role" {
  name = "rds_auth_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}


#Creating iam policy and attaching the iam role 

resource "aws_iam_role_policy" "rds_auth_policy" {
  name = "rds_auth_policy"
  role = aws_iam_role.rds_auth_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": [
        "arn:aws:rds-db:region:account-id:dbuser:db-identifier/db-user-name"
      ]
    }
  ]
}
EOF
}

#Creating rds
resource "aws_db_instance" "example" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
#  name                = "example"
  username             = var.rds_username
  password             = var.rds_password
  parameter_group_name = "default.mysql5.7"
  iam_database_authentication_enabled = true
  db_subnet_group_name = "${aws_db_subnet_group.db-subnet.name}"
}




===================================================================================

[root@ip-172-31-35-207 test5]# cat cw_agent_config.json
{
  "agent": {
    "metrics_collection_interval": 10
  },
  "metrics": {
    "metrics_collected": {
      "disk": {
        "resources": ["/", "/tmp"],
        "measurement": ["disk_used_percent"],
        "ignore_file_system_types": ["sysfs", "devtmpfs"]
      },
      "mem": {
        "measurement": ["mem_available_percent"]
      }
    },
    "aggregation_dimensions": [["InstanceId", "InstanceType"], ["InstanceId"]]
  }
}




=============================================================================
