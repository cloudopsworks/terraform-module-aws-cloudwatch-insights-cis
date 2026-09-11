##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

# Pattern-mode alarms count only events that survive all configured exact and pattern
# exclusions. A single series avoids false positives from delayed exclusion metrics.
resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.metric_filter_rules
  name           = each.key
  log_group_name = data.aws_cloudwatch_log_group.log_group.name
  pattern        = each.value.metric_filter_pattern

  metric_transformation {
    name          = format("%s-Matched", each.key)
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }

  lifecycle {
    precondition {
      condition     = length(each.value.metric_filter_pattern) <= 1024
      error_message = "The generated metric filter pattern for ${each.key} exceeds the CloudWatch Logs limit of 1024 characters."
    }
  }
}
