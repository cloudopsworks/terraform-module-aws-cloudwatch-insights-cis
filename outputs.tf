##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

output "cis_sns_topic_name" {
  value = aws_sns_topic.cis_alarm_topic.name
}

output "cis_sns_topic_arn" {
  value = aws_sns_topic.cis_alarm_topic.arn
}

output "cis_dashboard_name" {
  value = aws_cloudwatch_dashboard.this.dashboard_name
}

output "cis_dashboard_id" {
  value = aws_cloudwatch_dashboard.this.id
}

output "cis_alarms" {
  value = [
    for alarm in aws_cloudwatch_metric_alarm.this : {
      name = alarm.alarm_name
      arn  = alarm.arn
    }
  ]
}

output "cis_metric_filter_alarms" {
  description = "Rule names whose alarm is driven by a CloudWatch Logs metric filter instead of the Contributor Insights rule metric, because pattern-based exclusions are configured for them."
  value       = keys(local.metric_filter_rules)
}