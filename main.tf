##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

locals {
  insight_rules = [
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
  widgets = [
    for item in insight_rules : {
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
        region  = data.aws_region.current.id
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