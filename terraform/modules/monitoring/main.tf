# File: terraform/modules/monitoring/main.tf

# Monitoring module for SSHoney

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs"
  type        = list(string)
}

variable "security_group_id" {
  description = "Security group ID for monitoring access"
  type        = string
}

variable "alert_emails" {
  description = "Email addresses for alerts"
  type        = list(string)
  default     = []
}

variable "autoscaling_group_name" {
  description = "Name of the Auto Scaling Group to monitor"
  type        = string
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "sshoney" {
  dashboard_name = "${var.project_name}-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", var.autoscaling_group_name],
            [".", "NetworkIn", ".", "."],
            [".", "NetworkOut", ".", "."],
            [".", "NetworkPacketsIn", ".", "."],
            [".", "NetworkPacketsOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "EC2 Metrics"
          period  = 300
          stat    = "Average"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", "${var.project_name}-${var.environment}-alb"],
            [".", "RequestCount", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Load Balancer Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          query   = <<-EOT
            SOURCE '/aws/ec2/${var.project_name}-${var.environment}'
            | fields @timestamp, @message
            | filter @message like /ACCEPT/
            | parse @message /host=(?<ip>[0-9.]+)/
            | stats count() as connections by bin(5m)
            | sort @timestamp desc
            | limit 100
          EOT
          region  = data.aws_region.current.name
          title   = "SSHoney Connections Over Time"
          view    = "table"
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 12
        height = 6

        properties = {
          query   = <<-EOT
            SOURCE '/aws/ec2/${var.project_name}-${var.environment}'
            | fields @timestamp, @message
            | filter @message like /ACCEPT/
            | parse @message /host=(?<ip>[0-9.]+)/
            | stats count() as connections by ip
            | sort connections desc
            | limit 20
          EOT
          region  = data.aws_region.current.name
          title   = "Top Attacking IPs"
          view    = "table"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 12
        width  = 12
        height = 6

        properties = {
          query   = <<-EOT
            SOURCE '/aws/ec2/${var.project_name}-${var.environment}'
            | fields @timestamp, @message
            | filter @message like /CLOSE/
            | parse @message /time=(?<duration>[0-9.]+)/
            | stats avg(duration) as avg_duration, max(duration) as max_duration, count() as total_sessions by bin(1h)
            | sort @timestamp desc
          EOT
          region  = data.aws_region.current.name
          title   = "Session Duration Statistics"
          view    = "table"
        }
      }
    ]
  })
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.project_name}-${var.environment}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EC2 CPU utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = var.autoscaling_group_name
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "high_network_in" {
  alarm_name          = "${var.project_name}-${var.environment}-high-network-in"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NetworkPacketsIn"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50000"
  alarm_description   = "High number of incoming network packets (potential DDoS)"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = var.autoscaling_group_name
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "low_healthy_hosts" {
  alarm_name          = "${var.project_name}-${var.environment}-low-healthy-hosts"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "Number of healthy hosts is too low"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    TargetGroup  = aws_cloudwatch_log_metric_filter.connection_rate.name
    LoadBalancer = "${var.project_name}-${var.environment}-nlb"
  }

  tags = {
    Environment = var.environment
  }
}

# Custom metric from logs
resource "aws_cloudwatch_log_metric_filter" "connection_rate" {
  name           = "${var.project_name}-${var.environment}-connection-rate"
  log_group_name = "/aws/ec2/${var.project_name}-${var.environment}"
  pattern        = "[timestamp, level=\"ACCEPT\", ...]"

  metric_transformation {
    name      = "SSHoneyConnectionRate"
    namespace = "SSHoney"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_connection_rate" {
  alarm_name          = "${var.project_name}-${var.environment}-high-connection-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "SSHoneyConnectionRate"
  namespace           = "SSHoney"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "High connection rate detected"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  tags = {
    Environment = var.environment
  }
}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${var.environment}-alerts"

  tags = {
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "email" {
  count     = length(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

# CloudWatch Log Insights Queries
resource "aws_cloudwatch_query_definition" "top_attacking_ips" {
  name = "${var.project_name}-${var.environment}/top-attacking-ips"

  log_group_names = [
    "/aws/ec2/${var.project_name}-${var.environment}"
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /ACCEPT/
| parse @message /host=(?<ip>[0-9.]+)/
| stats count() as connections by ip
| sort connections desc
| limit 50
EOF
}

resource "aws_cloudwatch_query_definition" "connection_timeline" {
  name = "${var.project_name}-${var.environment}/connection-timeline"

  log_group_names = [
    "/aws/ec2/${var.project_name}-${var.environment}"
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /ACCEPT/
| parse @message /host=(?<ip>[0-9.]+)/
| stats count() as connections by bin(1h)
| sort @timestamp desc
EOF
}

resource "aws_cloudwatch_query_definition" "geographic_analysis" {
  name = "${var.project_name}-${var.environment}/geographic-analysis"

  log_group_names = [
    "/aws/ec2/${var.project_name}-${var.environment}"
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /ACCEPT/
| parse @message /host=(?<ip>[0-9.]+)/
| stats count() as connections by ip
| sort connections desc
| limit 100
EOF
}

resource "aws_cloudwatch_query_definition" "session_duration_analysis" {
  name = "${var.project_name}-${var.environment}/session-duration"

  log_group_names = [
    "/aws/ec2/${var.project_name}-${var.environment}"
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /CLOSE/
| parse @message /host=(?<ip>[0-9.]+).*time=(?<duration>[0-9.]+)/
| stats avg(duration) as avg_duration, max(duration) as max_duration, min(duration) as min_duration, count() as sessions by ip
| sort avg_duration desc
| limit 50
EOF
}

# Data source
data "aws_region" "current" {}

# Outputs
output "dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.sshoney.dashboard_name}"
}

output "sns_topic_arn" {
  description = "SNS Topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "log_insights_queries" {
  description = "CloudWatch Log Insights query names"
  value = [
    aws_cloudwatch_query_definition.top_attacking_ips.name,
    aws_cloudwatch_query_definition.connection_timeline.name,
    aws_cloudwatch_query_definition.geographic_analysis.name,
    aws_cloudwatch_query_definition.session_duration_analysis.name
  ]
}