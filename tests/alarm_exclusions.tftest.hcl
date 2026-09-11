##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

# Mocked plans validate generated configuration without AWS credentials.
# AWS TestMetricFilter is still required to verify live matching semantics.
mock_provider "aws" {
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:123456789012:cis-test" }
  }
  mock_data "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail/test"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
}

variables {
  org = {
    organization_name = "test"
    organization_unit = "security"
    environment_type  = "test"
    environment_name  = "test"
  }
  settings = {
    log_group_name = "/aws/cloudtrail/test"
  }
}

run "no_exclusions" {
  command = plan

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this) == 14 && length(aws_cloudwatch_log_metric_filter.this) == 0
    error_message = "Without exclusions, all 14 alarms must use Contributor Insights."
  }
}

run "combined_exact_and_pattern_exclusions" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        security_groups              = ["sg-excluded-a", "sg-excluded-b"]
        security_group_names         = ["excluded-sg", "another-sg"]
        security_group_name_patterns = ["generated-*"]
        iam_roles                    = ["excluded-role", "another-role"]
        iam_role_patterns            = ["generated-*"]
      }
    }
  }

  assert {
    condition = alltrue([
      for role in var.settings.exclude.iam_roles :
      strcontains(aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern, format("$.requestParameters.roleName != %s", jsonencode(role)))
    ])
    error_message = "Pattern mode must not count exact-excluded IAM roles in the alarm's total."
  }

  assert {
    condition = alltrue(concat(
      [for id in var.settings.exclude.security_groups :
        strcontains(aws_cloudwatch_log_metric_filter.this["CIS-Security-Group-Changes"].pattern, format("$.requestParameters.groupId != %s", jsonencode(id)))
      ],
      [for name in var.settings.exclude.security_group_names :
        strcontains(aws_cloudwatch_log_metric_filter.this["CIS-Security-Group-Changes"].pattern, format("$.requestParameters.groupName != %s", jsonencode(name)))
      ],
    ))
    error_message = "Pattern mode must not count exact-excluded security group IDs or names in the alarm's total."
  }

  assert {
    condition = (
      strcontains(aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern, "$.requestParameters.roleName = * && $.requestParameters.roleName != \"excluded-role\" && $.requestParameters.roleName != \"another-role\" &&") &&
      strcontains(aws_cloudwatch_log_metric_filter.this["CIS-Security-Group-Changes"].pattern, "$.requestParameters.groupId = * && $.requestParameters.groupId != \"sg-excluded-a\" && $.requestParameters.groupId != \"sg-excluded-b\" &&") &&
      strcontains(aws_cloudwatch_log_metric_filter.this["CIS-Security-Group-Changes"].pattern, "$.requestParameters.groupName = * && $.requestParameters.groupName != \"excluded-sg\" && $.requestParameters.groupName != \"another-sg\" &&")
    )
    error_message = "Each exact list must require its field and AND every rejection with the pattern conditions."
  }

  assert {
    condition = alltrue([
      for name in ["CIS-IAM-Changes", "CIS-Security-Group-Changes"] :
      length(local.alarm_metric_queries[name]) == 1 &&
      local.alarm_metric_queries[name][0].metric_name == "${name}-Matched" &&
      local.alarm_metric_queries[name][0].expression == null
    ])
    error_message = "The alarm must read one fresh filtered metric, never total minus a possibly late excluded series."
  }

}

run "disabled_rules_with_exclusions" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      rules = {
        iam_changes = { enabled = false }
        sg_changes  = { enabled = false }
      }
      exclude = {
        iam_role_patterns            = ["generated-*"]
        security_group_name_patterns = ["generated-*"]
      }
    }
  }
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this) == 12 && length(aws_cloudwatch_log_metric_filter.this) == 0
    error_message = "Disabled rules must not render alarms or metric filters even with exclusions."
  }
}

run "pattern_only_direct_matching" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_role_patterns            = ["*-exec-role", "%^svc-[a-z]+-role$%"]
        security_group_name_patterns = ["generated-*", "*-temporary"]
      }
    }
  }
  assert {
    condition = strcontains(
      aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern,
      "(($.requestParameters.roleName NOT EXISTS) || ($.requestParameters.roleName IS NULL) || ($.requestParameters.roleName != \"*-exec-role\" && $.requestParameters.roleName != %^svc-[a-z]+-role$%))",
    )
    error_message = "Reject any matching wildcard or regex (AND the negative conditions), while retaining absent/null names."
  }
  assert {
    condition = strcontains(
      aws_cloudwatch_log_metric_filter.this["CIS-Security-Group-Changes"].pattern,
      "(($.requestParameters.groupName NOT EXISTS) || ($.requestParameters.groupName IS NULL) || ($.requestParameters.groupName != \"generated-*\" && $.requestParameters.groupName != \"*-temporary\"))",
    )
    error_message = "Security group pattern-only mode must preserve ID-only events and reject either matching name pattern."
  }
  assert {
    condition = alltrue([
      for name, filter in aws_cloudwatch_log_metric_filter.this :
      one(filter.metric_transformation).name == "${name}-Matched" &&
      one(filter.metric_transformation).default_value == "0" &&
      one(aws_cloudwatch_metric_alarm.this[name].metric_query).expression == null &&
      one(one(aws_cloudwatch_metric_alarm.this[name].metric_query).metric).metric_name == "${name}-Matched" &&
      one(one(aws_cloudwatch_metric_alarm.this[name].metric_query).metric).stat == "Sum" &&
      one(one(aws_cloudwatch_metric_alarm.this[name].metric_query).metric).period == 300
    ])
    error_message = "Each pattern alarm must read only its filtered five-minute count, with zero defaults and no subtraction."
  }
}

run "exact_only_preserves_contributor_insights" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_roles            = ["excluded-role"]
        security_groups      = ["sg-excluded"]
        security_group_names = ["excluded-sg"]
        unauthorized_events  = ["CreateUser"]
        unauthorized_sources = ["iam.amazonaws.com"]
      }
    }
  }
  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 0 && length(aws_cloudwatch_metric_alarm.this) == 14
    error_message = "Exact-only exclusions must preserve the existing Contributor Insights alarm path."
  }
  assert {
    condition = alltrue([
      for entry in [
        { rule = "CIS-IAM-Changes", field = "$.requestParameters.roleName", value = "excluded-role" },
        { rule = "CIS-Security-Group-Changes", field = "$.requestParameters.groupId", value = "sg-excluded" },
        { rule = "CIS-Security-Group-Changes", field = "$.requestParameters.groupName", value = "excluded-sg" },
        { rule = "CIS-Unauthorized-API-Activity", field = "$.eventName", value = "CreateUser" },
        { rule = "CIS-Unauthorized-API-Activity", field = "$.eventSource", value = "iam.amazonaws.com" },
        ] : anytrue([
          for filter in jsondecode(aws_cloudwatch_contributor_insight_rule.this[entry.rule].rule_definition).Contribution.Filters :
          filter.Match == entry.field && try(contains(filter.NotIn, entry.value), false)
      ])
    ])
    error_message = "Every exact exclusion must remain in its Contributor Insights rule."
  }
}

run "policy_name_exact_and_pattern_exclusions" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_roles                = ["excluded-role"]
        iam_role_patterns        = ["*-exec-role"]
        iam_policy_names         = ["excluded-policy", "another-policy"]
        iam_policy_name_patterns = ["AWSLambdaBasicExecutionRole-*", "%^inline-[a-z]+$%"]
      }
    }
  }
  assert {
    condition = strcontains(
      aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern,
      "$.requestParameters.policyName = * && $.requestParameters.policyName != \"excluded-policy\" && $.requestParameters.policyName != \"another-policy\" &&",
    )
    error_message = "The exact policy-name list must require policyName and reject every listed value in the alarm filter."
  }
  assert {
    condition = strcontains(
      aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern,
      "(($.requestParameters.policyName NOT EXISTS) || ($.requestParameters.policyName IS NULL) || ($.requestParameters.policyName != \"AWSLambdaBasicExecutionRole-*\" && $.requestParameters.policyName != %^inline-[a-z]+$%))",
    )
    error_message = "Policy-name patterns must be ANDed as negatives while retaining absent/null policy names."
  }
  assert {
    condition = strcontains(
      aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern,
      "(($.requestParameters.roleName NOT EXISTS) || ($.requestParameters.roleName IS NULL) || ($.requestParameters.roleName != \"*-exec-role\"))",
    )
    error_message = "Role-name patterns must still apply alongside policy-name patterns."
  }
  assert {
    condition = anytrue([
      for filter in jsondecode(aws_cloudwatch_contributor_insight_rule.this["CIS-IAM-Changes"].rule_definition).Contribution.Filters :
      filter.Match == "$.requestParameters.policyName" && try(contains(filter.NotIn, "excluded-policy"), false)
    ])
    error_message = "The exact policy-name list must become a NotIn filter on the Contributor Insights rule."
  }
  assert {
    condition     = length(jsondecode(aws_cloudwatch_contributor_insight_rule.this["CIS-IAM-Changes"].rule_definition).Contribution.Filters) == 4
    error_message = "With both exact IAM lists set, the Contributor Insights rule must hold exactly 4 filters (the API maximum)."
  }
}

run "policy_name_patterns_only_switch_alarm" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_policy_name_patterns = ["*-inline-policy"]
      }
    }
  }
  assert {
    condition = (
      length(aws_cloudwatch_log_metric_filter.this) == 1 &&
      strcontains(aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern, "$.requestParameters.policyName != \"*-inline-policy\"") &&
      !strcontains(aws_cloudwatch_log_metric_filter.this["CIS-IAM-Changes"].pattern, "roleName")
    )
    error_message = "A policy-name pattern alone must switch only the IAM alarm to the filtered metric, without any roleName condition."
  }
}

run "policy_name_exact_only_preserves_contributor_insights" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_policy_names = ["excluded-policy"]
      }
    }
  }
  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 0 && length(aws_cloudwatch_metric_alarm.this) == 14
    error_message = "An exact policy-name list alone must keep the Contributor Insights alarm path."
  }
}

run "combined_iam_regex_limit_rejected" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_role_patterns        = ["%^a$%", "%^b$%"]
        iam_policy_name_patterns = ["%^c$%"]
      }
    }
  }
  expect_failures = [var.settings]
}

run "oversized_pattern_rejected" {
  command = plan
  variables {
    settings = {
      log_group_name = "/aws/cloudtrail/test"
      exclude = {
        iam_role_patterns = ["${join("", [for i in range(200) : "long-name"])}*"]
      }
    }
  }
  expect_failures = [aws_cloudwatch_log_metric_filter.this]
}
