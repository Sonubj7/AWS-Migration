variable "name" {
    description = "Name of the Project"
    type = string

}

variable "prod_name" {
    description = "Name of the sub project for production"
    type = string

}


variable "qa_name" {
    description = "Name of the sub project for QA"
    type = string

}

variable "iam_group_administrators_name" {
    description = "Name of the IAM Group for Administartors"
    type = string

}

variable "iam_user_administrators_name" {
    description = "Name of the IAM User for Administartors"
    type = string

}

variable "iam_user_developer_name" {
    description = "Name of the IAM User for DEveloper"
    type = string

}

variable "iam_group_developer_name" {
    description = "Name of the IAM group for Developer"
    type = string

}

variable "iam_user_qa_name" {
    description = "Name of the IAM user for QA"
    type = string

}

variable "ami_instance_cloudwatch" {
    description = "Name of the ami instance for cloudwatch"
    type = string

}

variable "key_name" {
    description = "Key to access the EC2 instance in cloud watch"
    type = string
   
}

variable "iam_instance_profile_name" {
    description = "Name of the instance profile  for cloudwatch"
    type = string

}

variable "vpc_name" {
    description = "Name of the vpc  for autoscaling"
    type = string

}

variable "vpc_address_space_range" {
    description = "Address space range of the vpc"

}


variable "subnet2_address_prefixes_range" {
    description = "Address space range of subnet 2"

}

variable "internet_gateway_name" {
    description = "Internet Gateway Name"

}

variable "internet_gateway_name" {
    description = "Internet Gateway Name"

}

variable "autoscaling_group_name" {
    description = "Name of the autoscaling group"

}

variable "rds_username" {
    description = "Username for the rds"

}

variable "rds_password" {
    description = "Password of RDS"

}

