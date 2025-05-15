##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

module "contributor_insights" {
  source     = "git::https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights.git?ref=develop"
  is_hub     = var.is_hub
  org        = var.org
  spoke_def  = var.spoke_def
  extra_tags = var.extra_tags
  insight_rules = [
    {
      name = "CIS-Unauthorized-API-Activity"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "AccessDenied",
                "UnauthorizedOperation"
              ],
              "Match" = "$.errorCode"
            }
          ],
          "Keys" = [
            "$.userIdentity.arn",
            "$.eventName"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-Console-Signin-Without-MFA"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "ConsoleLogin"
              ],
              "Match" = "$.eventName"
            },
            {
              "NotIn" = [
                "Yes"
              ],
              "Match" = "$.additionalEventData.MFAUsed"
            }
          ],
          "Keys" = [
            "$.userIdentity.userName",
            "$.sourceIPAddress"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-Root-Activity"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "Root"
              ],
              "Match" = "$.userIdentity.type"
            },
            {
              "IsPresent" = false,
              "Match"     = "$.userIdentity.invokedBy"
            },
            {
              "NotIn" = [
                "AwsServiceEvent"
              ],
              "Match" = "$.eventType"
            }
          ],
          "Keys" = [
            "$.userIdentity.type",
            "$.eventName"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-CloudTrail-Configuration-Changes"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "CreateTrail",
                "UpdateTrail",
                "DeleteTrail",
                "StartLogging",
                "StopLogging"
              ],
              "Match" = "$.eventName"
            }
          ],
          "Keys" = [
            "$.userIdentity.sessionContext.sessionIssuer.arn",
            "$.sourceIPAddress"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-Console-Authentication-Failures"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "ConsoleLogin"
              ],
              "Match" = "$.eventName"
            },
            {
              "In" = [
                "Failed authentication"
              ],
              "Match" = "$.errorMessage"
            }
          ],
          "Keys" = [
            "$.userIdentity.userName",
            "$.sourceIPAddress"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-CMK-Deletion-Disabling"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "DeleteAlias",
                "DisableKey",
                "ScheduleKeyDeletion"
              ],
              "Match" = "$.eventName"
            }
          ],
          "Keys" = [
            "$.userIdentity.arn",
            "$.sourceIPAddress"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    {
      name = "CIS-S3-Bucket-Policy-Changes"
      rule_definition = {
        "Schema" = {
          "Name"    = "CloudWatchLogRule",
          "Version" = 1
        },
        "AggregateOn" = "Count",
        "Contribution" = {
          "Filters" = [
            {
              "In" = [
                "s3.amazonaws.com"
              ],
              "Match" = "$.eventSource"
            },
            {
              "In" = [
                "PutBucketAcl",
                "PutBucketPolicy",
                "PutBucketCors",
                "PutBucketLifecycle",
                "PutBucketReplication",
                "DeleteBucketPolicy",
                "DeleteBucketCors",
                "DeleteBucketLifecycle",
                "DeleteBucketReplication"
              ],
              "Match" = "$.eventName"
            }
          ],
          "Keys" = [
            "$.userIdentity.sessionContext.sessionIssuer.arn",
            "$.sourceIPAddress"
          ]
        },
        "LogFormat" = "JSON",
        "LogGroupNames" = [
          var.settings.log_group_name
        ]
      }
    },
    # {
    #   name = "CIS-AWS-Config-Configuration-Changes"
    #   rule_definition = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "In" = [
    #             "config.amazonaws.com"
    #           ],
    #           "Match" = "$.eventSource"
    #         },
    #         {
    #           "In" = [
    #             "StopConfigurationRecorder",
    #             "DeleteDeliveryChannel",
    #             "PutDeliveryChannel",
    #             "PutConfigurationRecorder"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # },
    # {
    #   name = "CIS-Security-Group-Changes"
    #   rule_definition = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "In" = [
    #             "AuthorizeSecurityGroupIngress",
    #             "AuthorizeSecurityGroupEgress",
    #             "RevokeSecurityGroupIngress",
    #             "RevokeSecurityGroupEgress",
    #             "CreateSecurityGroup",
    #             "DeleteSecurityGroup"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.sessionContext.sessionIssuer.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # },
    # {
    #   name = "CIS-Network-ACL-Changes"
    #   rule_definition = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "In" = [
    #             "CreateNetworkAcl",
    #             "CreateNetworkAclEntry",
    #             "DeleteNetworkAcl",
    #             "DeleteNetworkAclEntry",
    #             "ReplaceNetworkAclEntry",
    #             "ReplaceNetworkAclAssociation"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # },
    # {
    #   name = "CIS-Network-Gateway-Changes"
    #   rule_definiton = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "In" = [
    #             "CreateCustomerGateway",
    #             "DeleteCustomerGateway",
    #             "AttachInternetGateway",
    #             "CreateInternetGateway",
    #             "DeleteInternetGateway",
    #             "DetachInternetGateway"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # },
    # {
    #   name = "CIS-Route-Table-Changes"
    #   rule_definition = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "In" = [
    #             "CreateRoute",
    #             "CreateRouteTable",
    #             "ReplaceRoute",
    #             "ReplaceRouteTableAssociation",
    #             "DeleteRouteTable",
    #             "DeleteRoute",
    #             "DisassociateRouteTable"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # },
    # {
    #   name = "CIS-VPC-Changes"
    #   rule_definition = {
    #     "Schema" = {
    #       "Name"    = "CloudWatchLogRule",
    #       "Version" = 1
    #     },
    #     "AggregateOn" = "Count",
    #     "Contribution" = {
    #       "Filters" = [
    #         {
    #           "StartsWith" = [
    #             "CreateVpc",
    #             "DeleteVpc",
    #             "ModifyVpcAttribute",
    #             "AcceptVpcPeeringConnection",
    #             "RejectVpcPeeringConnection",
    #             "AttachClassicLinkVpc",
    #             "DetachClassicLinkVpc",
    #             "DisableVpcClassicLink",
    #             "EnableVpcClassicLink"
    #           ],
    #           "Match" = "$.eventName"
    #         }
    #       ],
    #       "Keys" = [
    #         "$.userIdentity.arn",
    #         "$.sourceIPAddress"
    #       ]
    #     },
    #     "LogFormat" = "JSON",
    #     "LogGroupNames" = [
    #       var.settings.log_group_name
    #     ]
    #   }
    # }
  ]
}