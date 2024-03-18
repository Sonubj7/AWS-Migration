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
cd /tmp
mkdir logs
cp -r /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log /tmp/logs/amazon-cloudwatch-agent.log
cp -r /var/log/messages  /tmp/logs/messages
cp -r /var/log/nginx/access.log /tmp/logs/access.log
vi alllogs.log
cat access.log amazon-cloudwatch-agent.log messages > alllogs.log
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
 -a fetch-config \
 -m ec2 \
 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
amazon-linux-extras install nginx
service nginx start
echo 'Done initialization'
