##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

locals {
  api_calls = {
    name              = "CIS-Unauthorized-API-Activity"
    title             = "Unauthorized API Calls"
    alarm_description = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = concat([
          {
            In = [
              "AccessDenied",
              "UnauthorizedOperation",
            ]
            Match = "$.errorCode"
          },
          ],
          length(try(var.settings.exclude.unauthorized_sources, [])) > 0 ? [
            {
              NotIn = var.settings.exclude.unauthorized_sources
              Match = "$.eventSource"
            },
          ] : [],
          length(try(var.settings.exclude.unauthorized_events, [])) > 0 ? [
            {
              NotIn = var.settings.exclude.unauthorized_events
              Match = "$.eventName"
            },
        ] : [])
        Keys = [
          "$.userIdentity.arn",
          "$.eventName",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  console_signin = {
    name              = "CIS-Console-Signin-Without-MFA"
    title             = "Console Signin Without MFA"
    alarm_description = "Monitoring of Console Sign-in without MFA will help to detect unauthorized access to the AWS Management Console."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "ConsoleLogin",
            ]
            Match = "$.eventName"
          },
          {
            Match = "$.additionalEventData.MFAUsed"
            NotIn = [
              "Yes",
            ]
          },
        ]
        Keys = [
          "$.userIdentity.userName",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  root_activity = {
    name              = "CIS-Root-Activity"
    title             = "Root Activity"
    alarm_description = "Monitoring of Root Activity to detect unauthorized access to the root account."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "Root",
            ]
            Match = "$.userIdentity.type"
          },
          {
            IsPresent = false
            Match     = "$.userIdentity.invokedBy"
          },
          {
            Match = "$.eventType"
            NotIn = [
              "AwsServiceEvent",
            ]
          },
        ]
        Keys = [
          "$.userIdentity.type",
          "$.eventName",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  cloudtrail_changes = {
    name              = "CIS-CloudTrail-Configuration-Changes"
    title             = "CloudTrail Configuration Changes"
    alarm_description = "Monitoring of configuration changes to CloudTrail will help to detect unauthorized manipulation of CloudTrail."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "CreateTrail",
              "UpdateTrail",
              "DeleteTrail",
              "StartLogging",
              "StopLogging",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.sessionContext.sessionIssuer.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  console_failures = {
    name              = "CIS-Console-Authentication-Failures"
    title             = "Console Authentication Failures"
    alarm_description = "Monitoring of AWS Console Authentication Failures will help to detect unauthorized access or harvesting into the AWS Management Console."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "ConsoleLogin",
            ]
            Match = "$.eventName"
          },
          {
            In = [
              "Failed authentication",
            ]
            Match = "$.errorMessage"
          },
        ]
        Keys = [
          "$.userIdentity.userName",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  cmk_delete = {
    name              = "CIS-CMK-Deletion-Disabling"
    title             = "CMK Disabled or Deleted"
    alarm_description = "Monitoring of AWS Customer Managed Keys Deletion and Disable to detect unauthorized access to AWS KMS."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "kms.amazonaws.com",
            ]
            Match = "$.eventSource"
          },
          {
            In = [
              "DisableKey",
              "ScheduleKeyDeletion",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  s3_policy_changes = {
    name              = "CIS-S3-Bucket-Policy-Changes"
    title             = "S3 Bucket Policy Changes"
    alarm_description = "Monitoring of AWS S3 Bucket Policy Changes will help to detect unauthorized access to S3 buckets."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "s3.amazonaws.com",
            ]
            Match = "$.eventSource"
          },
          {
            In = [
              "PutBucketAcl",
              "PutBucketPolicy",
              "PutBucketCors",
              "PutBucketLifecycle",
              "PutBucketReplication",
              "DeleteBucketPolicy",
              "DeleteBucketCors",
              "DeleteBucketLifecycle",
              "DeleteBucketReplication",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.sessionContext.sessionIssuer.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  config_changes = {
    name              = "CIS-AWS-Config-Configuration-Changes"
    title             = "AWS Config Configuration Changes"
    alarm_description = "Monitoring of AWS Config Configuration Changes will help to detect unauthorized access to AWS Config."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "config.amazonaws.com",
            ]
            Match = "$.eventSource"
          },
          {
            In = [
              "StopConfigurationRecorder",
              "DeleteDeliveryChannel",
              "PutDeliveryChannel",
              "PutConfigurationRecorder",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  sg_changes = {
    name              = "CIS-Security-Group-Changes"
    title             = "Security Group Changes"
    alarm_description = "Monitoring of AWS VPC Security Group Changes will help to detect unauthorized access to VPC Security Groups."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "AuthorizeSecurityGroupIngress",
              "AuthorizeSecurityGroupEgress",
              "RevokeSecurityGroupIngress",
              "RevokeSecurityGroupEgress",
              "CreateSecurityGroup",
              "DeleteSecurityGroup",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.sessionContext.sessionIssuer.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  acl_changes = {
    name              = "CIS-Network-ACL-Changes"
    title             = "Network ACL Changes"
    alarm_description = "Monitoring of AWS VPC Network ACL Changes will help to detect unauthorized access to VPC Network ACLs."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "CreateNetworkAcl",
              "CreateNetworkAclEntry",
              "DeleteNetworkAcl",
              "DeleteNetworkAclEntry",
              "ReplaceNetworkAclEntry",
              "ReplaceNetworkAclAssociation",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  network_gw = {
    name              = "CIS-Network-Gateway-Changes"
    title             = "Network Gateway Changes"
    alarm_description = "Monitoring of AWS VPC Network Gateway Changes will help to detect unauthorized access to VPC Network Gateways."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "CreateCustomerGateway",
              "DeleteCustomerGateway",
              "AttachInternetGateway",
              "CreateInternetGateway",
              "DeleteInternetGateway",
              "DetachInternetGateway",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  route_table_changes = {
    name              = "CIS-Route-Table-Changes"
    title             = "Route Table Changes"
    alarm_description = "Monitoring of AWS VPC Route Table Changes will help to detect unauthorized access to VPC Route Tables."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "CreateRoute",
              "CreateRouteTable",
              "ReplaceRoute",
              "ReplaceRouteTableAssociation",
              "DeleteRouteTable",
              "DeleteRoute",
              "DisassociateRouteTable",
            ]
            Match = "$.eventName"
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  vpc_changes = {
    name              = "CIS-VPC-Changes"
    title             = "VPC Changes"
    alarm_description = "Monitoring of AWS VPC Changes will help to detect unauthorized access to VPCs."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            Match = "$.eventName"
            StartsWith = [
              "CreateVpc",
              "DeleteVpc",
              "ModifyVpcAttribute",
              "AcceptVpcPeeringConnection",
              "RejectVpcPeeringConnection",
              "AttachClassicLinkVpc",
              "DetachClassicLinkVpc",
              "DisableVpcClassicLink",
              "EnableVpcClassicLink",
            ]
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
  iam_changes = {
    name              = "CIS-IAM-Changes"
    title             = "IAM Changes"
    alarm_description = "Monitoring of all IAM Changes will help to detect unauthorized access to IAM."
    rule_state        = "ENABLED"
    body = {
      AggregateOn = "Count"
      Contribution = {
        Filters = [
          {
            In = [
              "iam.amazonaws.com",
            ]
            Match = "$.eventSource"
          },
          {
            Match = "$.eventName"
            StartsWith = [
              "Create",
              "Delete",
              "Update",
              "Add",
              "Remove",
              "Put",
              "Attach",
            ]
          },
        ]
        Keys = [
          "$.userIdentity.arn",
          "$.sourceIPAddress",
        ]
      }
      LogFormat = "JSON"
      LogGroupARNs = [
        data.aws_cloudwatch_log_group.log_group.arn,
      ]
      Schema = {
        Name    = "CloudWatchLogRule"
        Version = 1
      }
    }
  }
}

