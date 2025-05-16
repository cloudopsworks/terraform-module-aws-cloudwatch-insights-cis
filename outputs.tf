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

output "cis_unauthorized_api_activity_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_unauthorized_api_activity.arn
}