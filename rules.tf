##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

locals {
  api_calls = {
    name       = "CIS-Unauthorized-API-Activity"
    title      = "Unauthorized API Calls"
    rule_state = "ENABLED"
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
    name       = "CIS-Console-Signin-Without-MFA"
    title      = "Console Signin Without MFA"
    rule_state = "ENABLED"
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
    name       = "CIS-Root-Activity"
    title      = "Root Activity"
    rule_state = "ENABLED"
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
    name       = "CIS-CloudTrail-Configuration-Changes"
    title      = "CloudTrail Configuration Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-Console-Authentication-Failures"
    title      = "Console Authentication Failures"
    rule_state = "ENABLED"
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
    name       = "CIS-CMK-Deletion-Disabling"
    title      = "CMK Disabled or Deleted"
    rule_state = "ENABLED"
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
    name       = "CIS-S3-Bucket-Policy-Changes"
    title      = "S3 Bucket Policy Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-AWS-Config Configuration-Changes"
    title      = "AWS Config Configuration Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-Security-Group-Changes"
    title      = "Security Group Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-Network-ACL-Changes"
    title      = "Network ACL Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-Network-Gateway-Changes"
    title      = "Network Gateway Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-Route-Table-Changes"
    title      = "Route Table Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-VPC-Changes"
    title      = "VPC Changes"
    rule_state = "ENABLED"
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
    name       = "CIS-IAM-Changes"
    title      = "IAM Changes"
    rule_state = "ENABLED"
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

