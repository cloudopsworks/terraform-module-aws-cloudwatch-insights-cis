##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

resource "aws_cloudwatch_metric_alarm" "cis_unauthorized_api_activity" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Unauthorized-API-Activity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Unauthorized-API-Activity"
    expression  = "INSIGHT_RULE_METRIC('CIS-Unauthorized-API-Activity', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_console_signin_without_mfa" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Console-Signin-Without-MFA"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of Console Sign-in without MFA will help to detect unauthorized access to the AWS Management Console."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Console-Signin-Without-MFA"
    expression  = "INSIGHT_RULE_METRIC('CIS-Console-Signin-Without-MFA', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_root_activity" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Root-Activity"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of Root Activity to detect unauthorized access to the root account."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Root-Activity"
    expression  = "INSIGHT_RULE_METRIC('CIS-Root-Activity', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_cloudtrail_configuration_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-CloudTrail-Configuration-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of configuration changes to CloudTrail will help to detect unauthorized manipulation of CloudTrail."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-CloudTrail-Configuration-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-CloudTrail-Configuration-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_console_authentication_failures" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Console-Authentication-Failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS Console Authentication Failures will help to detect unauthorized access or harvesting into the AWS Management Console."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Console-Authentication-Failures"
    expression  = "INSIGHT_RULE_METRIC('CIS-Console-Authentication-Failures', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_cmk_deletion_disabling" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-CMK-Deletion-Disabling"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS Customer Managed Keys Deletion and Disable to detect unauthorized access to AWS KMS."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-CMK-Deletion-Disabling"
    expression  = "INSIGHT_RULE_METRIC('CIS-CMK-Deletion-Disabling', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_bucket_policy_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-S3-Bucket-Policy-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS S3 Bucket Policy Changes will help to detect unauthorized access to S3 buckets."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-S3-Bucket-Policy-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-S3-Bucket-Policy-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_config_configuration_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-AWS-Config-Configuration-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS Config Configuration Changes will help to detect unauthorized access to AWS Config."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-AWS-Config-Configuration-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-AWS-Config-Configuration-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_security_group_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Security-Group-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS VPC Security Group Changes will help to detect unauthorized access to VPC Security Groups."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Security-Group-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-Security-Group-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_network_acl_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Network-ACL-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS VPC Network ACL Changes will help to detect unauthorized access to VPC Network ACLs."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Network-ACL-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-Network-ACL-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_route_table_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-Route-Table-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS VPC Route Table Changes will help to detect unauthorized access to VPC Route Tables."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-Route-Table-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-Route-Table-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_vpc_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-VPC-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of AWS VPC Changes will help to detect unauthorized access to VPCs."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-VPC-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-VPC-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

resource "aws_cloudwatch_metric_alarm" "cis_iam_changes" {
  depends_on          = [aws_cloudformation_stack.contributor_insights]
  alarm_name          = "CIS-IAM-Changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  datapoints_to_alarm = "1"
  alarm_description   = "Monitoring of all IAM Changes will help to detect unauthorized access to IAM."
  alarm_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  ok_actions = [
    aws_sns_topic.cis_alarm_topic.arn,
  ]
  metric_query {
    id          = "rule_metric"
    label       = "CIS-IAM-Changes"
    expression  = "INSIGHT_RULE_METRIC('CIS-IAM-Changes', 'Sum')"
    period      = "300"
    return_data = true
  }
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = local.all_tags
}

