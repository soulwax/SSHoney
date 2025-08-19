# File: terraform/outputs.tf

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.sshoney_alb.dns_name
}

output "network_load_balancer_dns" {
  description = "DNS name of the network load balancer for SSH"
  value       = aws_lb.sshoney_nlb.dns_name
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

output "ssh_access_command" {
  description = "Command to access instances via SSH"
  value       = "ssh -i ${aws_key_pair.sshoney_key.key_name}.pem ubuntu@<instance-ip> -p ${var.ssh_port}"
}