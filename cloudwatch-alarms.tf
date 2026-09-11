##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
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

  # One query: either the Contributor Insights expression or a directly filtered metric.
  dynamic "metric_query" {
    for_each = local.alarm_metric_queries[each.key]
    content {
      id          = metric_query.value.id
      label       = metric_query.value.label
      expression  = metric_query.value.expression
      period      = metric_query.value.period
      return_data = metric_query.value.return_data

      dynamic "metric" {
        for_each = metric_query.value.metric_name != null ? [metric_query.value.metric_name] : []
        content {
          metric_name = metric.value
          namespace   = local.metric_namespace
          period      = 300
          stat        = "Sum"
        }
      }
    }
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags

  depends_on = [
    aws_cloudwatch_log_metric_filter.this,
  ]
}
