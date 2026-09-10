##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

# YAML sample for module inputs
# settings:
#   log_group_name: "/aws/cloudtrail/organization"  # (Required) Existing log group holding the CloudTrail events.
#   exclude:                                        # (Optional) Per-rule exclusions. Each list is an exact-match NotIn filter, max 10 values.
#     unauthorized_events:                          # (Optional) api_calls rule - $.eventName. Default: [].
#       - "CreateUser"
#       - "DeleteUser"
#     unauthorized_sources:                         # (Optional) api_calls rule - $.eventSource. Default: [].
#       - "macie2.amazonaws.com"
#       - "cloud9.amazonaws.com"
#     security_groups:                              # (Optional) sg_changes rule - $.requestParameters.groupId. Default: [].
#       - "sg-0a1b2c3d4e5f6a7b8"
#     security_group_names:                         # (Optional) sg_changes rule - $.requestParameters.groupName. Default: [].
#       - "eks-cluster-sg-prod"
#     iam_roles:                                    # (Optional) iam_changes rule - exact $.requestParameters.roleName values. Default: [].
#       - "ci-deployer"
#     iam_role_patterns:                            # (Optional) iam_changes ALARM - $.requestParameters.roleName patterns. "*" works in any position. Default: [].
#       - "cognito-lambda-auth-*"                   #   starts with
#       - "*-exec-role"                             #   ends with
#       - "*exec*"                                  #   contains
#       - "exact-role-name"                         #   exact, no wildcard
#       - "%^svc-[a-z]+-role$%"                     #   regex, only for what "*" cannot do
#   rules:                                          # (Optional) Per-rule switches, every rule is enabled by default.
#     api_calls:
#       enabled: true                               # (Optional) Unauthorized API Calls. Default: true
#     console_signin:
#       enabled: true                               # (Optional) Console Signin Without MFA. Default: true
#     root_activity:
#       enabled: true                               # (Optional) Root Activity. Default: true
#     cloudtrail_changes:
#       enabled: true                               # (Optional) CloudTrail Configuration Changes. Default: true
#     console_failures:
#       enabled: true                               # (Optional) Console Authentication Failures. Default: true
#     cmk_delete:
#       enabled: true                               # (Optional) CMK Disabled or Deleted. Default: true
#     s3_policy_changes:
#       enabled: true                               # (Optional) S3 Bucket Policy Changes. Default: true
#     config_changes:
#       enabled: true                               # (Optional) AWS Config Configuration Changes. Default: true
#     sg_changes:
#       enabled: true                               # (Optional) Security Group Changes. Default: true
#     acl_changes:
#       enabled: true                               # (Optional) Network ACL Changes. Default: true
#     network_gw:
#       enabled: true                               # (Optional) Network Gateway Changes. Default: true
#     route_table_changes:
#       enabled: true                               # (Optional) Route Table Changes. Default: true
#     vpc_changes:
#       enabled: true                               # (Optional) VPC Changes. Default: true
#     iam_changes:
#       enabled: true                               # (Optional) IAM Changes. Default: true

# Two kinds of exclusion, applied at different layers:
#
# 1. exact-match lists (unauthorized_events, unauthorized_sources, security_groups,
#    security_group_names, iam_roles) become NotIn filters on the Contributor Insights
#    rule itself. Contributor Insights offers no negated pattern operator (no
#    NotStartsWith, no wildcards, no regex), so these must be full values. Each rule
#    accepts at most 4 filters in total and each NotIn list at most 10 values.
#
# 2. pattern lists (iam_role_patterns) take "*" in any position - "prefix-*", "*-suffix",
#    "*substring*", or an exact name with no wildcard at all. They cannot be expressed as
#    a rule filter, so setting one switches that rule's ALARM onto a pair of CloudWatch
#    Logs metric filters: one counting every change the rule watches, one counting only
#    the changes to excluded roles, with the alarm evaluating total - excluded. The
#    Contributor Insights rule and its dashboard widget are untouched and still rank every
#    contributor, so excluded roles remain visible on the dashboard - only the alarm stops
#    firing for them.
#
#    A value wrapped in percent signs is passed through as a CloudWatch Logs regex
#    ("%^svc-[a-z]+-role$%") for what a wildcard cannot express. It is never needed for a
#    prefix, suffix or substring. At most 2 values may use the regex form - the API
#    rejects a third - and regex cannot contain parentheses; use "|" to group.
#
# Caveat: a NotIn filter is only satisfied by events that actually carry the matched
# field, so an exclusion narrows its rule to events where the field is present:
#   - exclude.security_groups matches $.requestParameters.groupId, which CreateSecurityGroup
#     does not carry (it reports the new id in responseElements).
#   - exclude.iam_roles matches $.requestParameters.roleName, which non-role IAM events
#     (CreateUser, CreatePolicy, CreateAccessKey, AttachUserPolicy, ...) do not carry.
# Set these only after confirming the resulting coverage against a real log group.
# exclude.iam_role_patterns is not affected by that trap: events with no roleName never
# match the exclusion filter, so they are never subtracted and stay in the alarm.
#
# CloudTrail does not log the target role's path on role events other than CreateRole, so
# roles cannot be excluded by IAM path (e.g. /my-path/) - match the role name instead.

variable "settings" {
  description = "Settings for the insights. Supports log_group_name (Required), exclude (Optional) for per-rule NotIn exclusions, and rules (Optional) where each rule key accepts enabled to switch the Contributor Insights rule, its alarm and its dashboard widget on or off. Default: {} - all rules enabled, no exclusions."
  type        = any
  default     = {}

  validation {
    condition = alltrue([
      for list_name in ["unauthorized_events", "unauthorized_sources", "security_groups", "security_group_names", "iam_roles"] :
      length(try(var.settings.exclude[list_name], [])) <= 10
    ])
    error_message = "Each settings.exclude list accepts at most 10 values - CloudWatch Contributor Insights limits a NotIn filter to 10 string values."
  }

  validation {
    condition = length([
      for pattern in try(var.settings.exclude.iam_role_patterns, []) : pattern
      if startswith(pattern, "%")
    ]) <= 2
    error_message = "settings.exclude.iam_role_patterns accepts at most 2 regex values (the %...% form) - CloudWatch Logs allows at most 2 regex per filter pattern. Combine them into a single regex with the | alternation operator."
  }

  validation {
    condition = alltrue([
      for pattern in try(var.settings.exclude.iam_role_patterns, []) :
      endswith(pattern, "%") && length(pattern) >= 3
      if startswith(pattern, "%")
    ])
    error_message = "A regex value in settings.exclude.iam_role_patterns must open and close with % and hold an expression between them, for example \"%.*-exec-role$%\"."
  }

  validation {
    condition = alltrue([
      for pattern in try(var.settings.exclude.iam_role_patterns, []) :
      !strcontains(pattern, "(") && !strcontains(pattern, ")")
      if startswith(pattern, "%")
    ])
    error_message = "CloudWatch Logs regex does not support parentheses, so a regex value in settings.exclude.iam_role_patterns cannot contain ( or ) - group alternatives with | instead."
  }
}
