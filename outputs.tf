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