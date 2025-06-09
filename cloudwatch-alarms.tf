##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = {
    for item in local.insight_rules : item.name => item
  }
  alarm_name          = each.value.name
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = each.value.alarm_description
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = each.value.name
    expression  = "INSIGHT_RULE_METRIC('${each.value.name}', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}