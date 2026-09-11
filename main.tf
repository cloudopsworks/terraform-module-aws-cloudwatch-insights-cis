##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

locals {
  all_insight_rules = [
    local.api_calls,
    local.console_signin,
    local.root_activity,
    local.cloudtrail_changes,
    local.console_failures,
    local.cmk_delete,
    local.s3_policy_changes,
    local.config_changes,
    local.sg_changes,
    local.acl_changes,
    local.network_gw,
    local.route_table_changes,
    local.vpc_changes,
    local.iam_changes,
  ]
  # Each rule can be switched off individually through
  # settings.rules.<key>.enabled - all rules are enabled by default.
  # Disabling a rule removes its Contributor Insights rule, its metric alarm
  # and its dashboard widget.
  insight_rules = [
    for item in local.all_insight_rules : item
    if try(tobool(var.settings.rules[item.key].enabled), true)
  ]
  # Namespace for the metric-filter-backed alarm metrics.
  metric_namespace = "CIS-Monitoring"

  # Rules whose alarm is driven by a CloudWatch Logs metric filter rather than by
  # INSIGHT_RULE_METRIC, because they carry pattern-based exclusions that a Contributor
  # Insights filter cannot express. Keyed by rule name, like the other resource maps.
  metric_filter_rules = {
    for item in local.insight_rules : item.name => item
    if try(item.metric_filter_pattern, null) != null
  }

  # Pattern-mode alarms read one filtered count. The new metric name avoids reusing
  # historical unfiltered totals during migration. Other rules retain Contributor Insights.
  alarm_metric_queries = {
    for item in local.insight_rules : item.name => (
      try(item.metric_filter_pattern, null) == null ? [
        {
          id          = "rule_metric"
          label       = item.name
          expression  = "INSIGHT_RULE_METRIC('${item.name}', 'Sum')"
          metric_name = null
          period      = 300
          return_data = true
        },
        ] : [
        {
          id          = "matched"
          label       = item.name
          expression  = null
          metric_name = format("%s-Matched", item.name)
          period      = null
          return_data = true
        },
      ]
    )
  }

  widgets = [
    for item in local.insight_rules : {
      height = 6
      properties = {
        insightRule = {
          maxContributorCount = 10
          orderBy             = "Sum"
          ruleName            = item.name
        }
        legend = {
          position = "right"
        }
        period  = 60
        region  = data.aws_region.current.region
        stacked = false
        title   = item.title
        view    = "timeSeries"
        yAxis = {
          left = {
            showUnits = false
          }
          right = {
            showUnits = false
          }
        }
      }
      type  = "metric"
      width = 12
      x     = 0
      y     = 12
    }
  ]
  dashboard_body = {
    widgets = local.widgets
  }
}
data "aws_cloudwatch_log_group" "log_group" {
  name = var.settings.log_group_name
}

resource "aws_cloudwatch_contributor_insight_rule" "this" {
  for_each = {
    for item in local.insight_rules : item.name => item
  }
  rule_name       = each.value.name
  rule_state      = try(each.value.rule_state, "ENABLED")
  rule_definition = jsonencode(each.value.body)
  tags            = local.all_tags
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = "CIS-Monitoring-Dashboard"
  dashboard_body = jsonencode(local.dashboard_body)
}