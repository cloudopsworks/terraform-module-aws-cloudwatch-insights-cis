##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

resource "aws_cloudwatch_metric_alarm" "cis_unauthorized_api_activity" {
  alarm_name          = "CIS-Unauthorized-API-Activity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = module.contributor_insights.insight_rules["CIS-Unauthorized-API-Activity"].id
  namespace           = "AWS/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  treat_missing_data        = "NotBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}
