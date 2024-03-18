Migrate resources from one region to another in AWS

## Prerequisites
1. Create  an instance in AWS by Terraform
2. Migrate all  the resource from one region to another
3. All users with different privelieges should migrate to another region. 
4. Create cloudwatch in the existing ec-2 instances to push all neccesary logs specifically cpu and memory and system logs
5. MFA should be enabled for all users for better useability



- INSTALLING CHOCOLATEY   #https://chocolatey.org/install

   `Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`

- Terraform 0.14.9 or later

  `choco install terraform`

- install git #https://git-scm.com/downloads
#### https://learn.hashicorp.com/tutorials/terraform/azure-build

## Login 

`aws login`
Find the id column for the acess_key you want to use.
Once you have chosen the account
access_key and secret_key with AWS CLI


save the output of this command because, we will use it in the next step

# Set your environment variables

- `$Env:access_key = "<ACCESS_KEY>"`
- `$Env:secret_key = "<SECRET_KEY>"`

## Write configuration

'git clone https://github.com/Sonubj7/AWS-Migration.git'

`cd AWS-Migration`

## check out main.tf file 

- `terraform init`
- `terraform fmt`
- `terraform validate`
- `terraform apply`
- `terraform show` 



-------------------------------------
