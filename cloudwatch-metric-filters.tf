##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

# Metric filters back the alarms of rules that carry pattern-based exclusions. A
# Contributor Insights rule filter cannot express them: it negates exact values only
# (NotIn), with no wildcard and no regex. A CloudWatch Logs filter pattern can, so the
# alarm for those rules is evaluated as total - excluded over the two metrics below.
# Created only for rules that define metric_filter_pattern.

# Every change the rule watches, with no exclusions applied.
resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.metric_filter_rules
  name           = each.key
  log_group_name = data.aws_cloudwatch_log_group.log_group.name
  pattern        = each.value.metric_filter_pattern

  metric_transformation {
    name          = each.key
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

# Only the changes whose role name matches an exclusion pattern. Subtracted from the
# total by the alarm, so these stop raising it while the Contributor Insights rule and
# its dashboard widget keep ranking every contributor.
resource "aws_cloudwatch_log_metric_filter" "excluded" {
  for_each       = local.metric_filter_rules
  name           = format("%s-excluded", each.key)
  log_group_name = data.aws_cloudwatch_log_group.log_group.name
  pattern        = each.value.metric_filter_exclude_pattern

  metric_transformation {
    name          = format("%s-Excluded", each.key)
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }

  lifecycle {
    precondition {
      condition     = length(each.value.metric_filter_exclude_pattern) <= 1024
      error_message = "The generated exclusion metric filter pattern for ${each.key} exceeds the CloudWatch Logs limit of 1024 characters - reduce the number or length of the exclusion patterns."
    }
  }
}
