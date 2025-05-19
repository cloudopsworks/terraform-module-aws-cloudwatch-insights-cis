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

output "cis_console_signin_without_mfa_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_console_signin_without_mfa.arn
}

output "cis_root_activity_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_root_activity.arn
}

output "cis_cloudtrail_configuration_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_cloudtrail_configuration_changes.arn
}

output "cis_console_authentication_failures_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_console_authentication_failures.arn
}

output "cis_cmk_deletion_disabling_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_cmk_deletion_disabling.arn
}

output "cis_bucket_policy_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_bucket_policy_changes.arn
}

output "cis_config_configuration_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_config_configuration_changes.arn
}

output "cis_security_group_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_security_group_changes.arn
}

output "cis_network_acl_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_network_acl_changes.arn
}

output "cis_route_table_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_route_table_changes.arn
}

output "cis_vpc_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_vpc_changes.arn
}

output "cis_iam_changes_alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cis_iam_changes.arn
}