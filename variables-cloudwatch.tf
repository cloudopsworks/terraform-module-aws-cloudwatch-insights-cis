##
# (c) 2021-2026
#     Cloud Ops Works LLC - https://cloudops.works/
#     Find us on:
#       GitHub: https://github.com/cloudopsworks
#       WebSite: https://cloudops.works
#     Distributed Under Apache v2.0 License
#

# YAML sample for module inputs
# settings:
#   log_group_name: "/aws/cloudtrail/organization"  # (Required) Existing log group holding the CloudTrail events.
#   exclude:                                        # (Optional) Per-rule exact and pattern exclusions; exact lists accept max 10 values. Default: omitted.
#     unauthorized_events:                          # (Optional) api_calls rule - $.eventName. Default: [].
#       - "CreateUser"
#       - "DeleteUser"
#     unauthorized_sources:                         # (Optional) api_calls rule - $.eventSource. Default: [].
#       - "macie2.amazonaws.com"
#       - "cloud9.amazonaws.com"
#     security_groups:                              # (Optional) sg_changes rule - $.requestParameters.groupId. Default: [].
#       - "sg-0a1b2c3d4e5f6a7b8"
#     security_group_names:                         # (Optional) sg_changes rule - exact $.requestParameters.groupName values. Default: [].
#       - "eks-cluster-sg-prod"
#     security_group_name_patterns:                 # (Optional) sg_changes ALARM - $.requestParameters.groupName patterns. Uses CIS-Security-Group-Changes-Matched; exact SG exclusions also apply. "*" works in any position. Default: [].
#       - "eks-cluster-sg-*"                        #   starts with
#       - "*-tmp-sg"                                #   ends with
#     iam_roles:                                    # (Optional) iam_changes rule - exact $.requestParameters.roleName values. Default: [].
#       - "ci-deployer"
#     iam_role_patterns:                            # (Optional) iam_changes ALARM - $.requestParameters.roleName patterns. Uses CIS-IAM-Changes-Matched; exact IAM-role exclusions also apply. "*" works in any position. Default: [].
#       - "cognito-lambda-auth-*"                   #   starts with
#       - "*-exec-role"                             #   ends with
#       - "*exec*"                                  #   contains
#       - "exact-role-name"                         #   exact, no wildcard
#       - "%^svc-[a-z]+-role$%"                     #   regex, only for what "*" cannot do
#     iam_policy_names:                             # (Optional) iam_changes rule - exact $.requestParameters.policyName values. Default: [].
#       - "ci-deployer-inline"
#     iam_policy_name_patterns:                     # (Optional) iam_changes ALARM - $.requestParameters.policyName patterns. Same forms and metric as iam_role_patterns; exact IAM exclusions also apply. Default: [].
#       - "AWSLambdaBasicExecutionRole-*"           #   starts with
#       - "*-inline-policy"                         #   ends with
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
#    security_group_names, iam_roles, iam_policy_names) become NotIn filters on the Contributor Insights
#    rule itself. Contributor Insights offers no negated pattern operator (no
#    NotStartsWith, no wildcards, no regex), so these must be full values. Each rule
#    accepts at most 4 filters in total and each NotIn list at most 10 values.
#
# 2. pattern lists (iam_role_patterns, iam_policy_name_patterns, security_group_name_patterns)
#    take "*" in any position - "prefix-*", "*-suffix",
#    "*substring*", or an exact name with no wildcard at all. They cannot be expressed as
#    a Contributor Insights filter, so setting one switches that rule's ALARM to one
#    directly filtered CloudWatch Logs metric, <rule-name>-Matched, in CIS-Monitoring.
#    The filter keeps only nonexcluded events and includes configured exact-list presence
#    and NotIn conditions. Contributor Insights/dashboard still apply exact exclusions,
#    while pattern-excluded events can remain visible there for investigation.
#
#    A value wrapped in percent signs is passed through as a CloudWatch Logs regex
#    ("%^svc-[a-z]+-role$%") for what a wildcard cannot express. It is never needed for a
#    prefix, suffix or substring. At most 2 values per rule may use the regex form - the
#    API rejects a third - and regex cannot contain parentheses; use "|" to group. The two
#    iam_changes pattern lists share one filter pattern, so their regex count is combined.
#
# Caveat: a NotIn filter is only satisfied by events that actually carry the matched
# field, so an exclusion narrows its rule to events where the field is present:
#   - exclude.security_groups matches $.requestParameters.groupId, which CreateSecurityGroup
#     does not carry (it reports the new id in responseElements).
#   - exclude.iam_roles matches $.requestParameters.roleName, which non-role IAM events
#     (CreateUser, CreatePolicy, CreateAccessKey, AttachUserPolicy, ...) do not carry.
#   - exclude.iam_policy_names matches $.requestParameters.policyName, which only inline
#     policy events (Put/Delete{Role,User,Group}Policy) and CreatePolicy carry. Attach*,
#     Detach* and CreatePolicyVersion identify the policy by policyArn, not by name.
#   - setting BOTH exclude.iam_roles and exclude.iam_policy_names narrows iam_changes to
#     events carrying both fields - PutRolePolicy and DeleteRolePolicy only.
# Set these only after confirming the resulting coverage against a real log group.
# A missing or null name never matches a pattern and remains in the pattern-mode alarm,
# unless a configured exact exclusion requires that field to be present.
#
# exclude.security_group_name_patterns is narrow for the same reason. groupName reaches
# CloudTrail only on CreateSecurityGroup and on legacy name-based Authorize/Revoke calls;
# in a VPC, Authorize, Revoke and Delete identify the group by groupId, and group ids are
# random and cannot be pattern matched. Excluding a group by name therefore mutes the
# alarm for its CREATION only - rule changes on it keep alarming.
#
# CloudTrail does not log the target role's path on role events other than CreateRole, so
# roles cannot be excluded by IAM path (e.g. /my-path/) - match the role name instead.

variable "settings" {
  description = "Settings for the insights. Supports log_group_name (Required), exclude (Optional) for per-rule exact NotIn lists and alarm-only name-pattern lists, and rules (Optional) where each rule key accepts enabled to switch the Contributor Insights rule, its alarm and its dashboard widget on or off. Default: {} - all rules enabled, no exclusions."
  type        = any
  default     = {}

  validation {
    condition = alltrue([
      for list_name in ["unauthorized_events", "unauthorized_sources", "security_groups", "security_group_names", "iam_roles", "iam_policy_names"] :
      length(try(var.settings.exclude[list_name], [])) <= 10
    ])
    error_message = "Each settings.exclude list accepts at most 10 values - CloudWatch Contributor Insights limits a NotIn filter to 10 string values."
  }

  # Each rule feeds one filter pattern, so the 2 regex limit applies per rule - the two
  # iam_changes lists count together.
  validation {
    condition = alltrue([
      for rule_lists in [["iam_role_patterns", "iam_policy_name_patterns"], ["security_group_name_patterns"]] :
      length([
        for pattern in flatten([for list_name in rule_lists : try(var.settings.exclude[list_name], [])]) : pattern
        if startswith(pattern, "%")
      ]) <= 2
    ])
    error_message = "The pattern lists under settings.exclude accept at most 2 regex values (the %...% form) per rule - iam_role_patterns and iam_policy_name_patterns combined, and security_group_name_patterns on its own - because CloudWatch Logs allows at most 2 regex per filter pattern. Combine them into a single regex with the | alternation operator."
  }

  validation {
    condition = alltrue([
      for pattern in concat(
        try(var.settings.exclude.iam_role_patterns, []),
        try(var.settings.exclude.iam_policy_name_patterns, []),
        try(var.settings.exclude.security_group_name_patterns, []),
      ) :
      endswith(pattern, "%") && length(pattern) >= 3
      if startswith(pattern, "%")
    ])
    error_message = "A regex value in a settings.exclude pattern list must open and close with % and hold an expression between them, for example \"%.*-exec-role$%\"."
  }

  validation {
    condition = alltrue([
      for pattern in concat(
        try(var.settings.exclude.iam_role_patterns, []),
        try(var.settings.exclude.iam_policy_name_patterns, []),
        try(var.settings.exclude.security_group_name_patterns, []),
      ) :
      !strcontains(pattern, "(") && !strcontains(pattern, ")")
      if startswith(pattern, "%")
    ])
    error_message = "CloudWatch Logs regex does not support parentheses, so a regex value in a settings.exclude pattern list cannot contain ( or ) - group alternatives with | instead."
  }
}
