##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

resource "aws_cloudwatch_dashboard" "cis_dashboard" {
  dashboard_name = "CIS-Monitoring-Dashboard"
  dashboard_body = jsonencode({
    "widgets" = [
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Unauthorized-API-Activity"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Unauthorized API Calls",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Console-Signin-Without-MFA"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Console Signin Without MFA",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Root-Activity"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Root Activity",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-CloudTrail-Configuration-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "CloudTrail Configuration Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Console-Authentication-Failures"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Console Authentication Failures",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-CMK-Deletion-Disabling"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "CMK Disabled or Deleted",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-S3-Bucket-Policy-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "S3 Bucket Policy Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-AWS-Config-Configuration-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "AWS Config Configuration Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Security-Group-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Security Group Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Network-ACL-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Network ACL Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Network-Gateway-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Network Gateway Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-Route-Table-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "Route Table Changes",
          "legend" = {
            "position" = "right"
          }
        }
      },
      {
        "type"   = "metric",
        "x"      = 0,
        "y"      = 12,
        "width"  = 12,
        "height" = 6,
        "properties" = {
          "period" = 60,
          "insightRule" = {
            "maxContributorCount" = 10,
            "orderBy"             = "Sum",
            "ruleName"            = "CIS-VPC-Changes"
          },
          "stacked" = false,
          "view"    = "timeSeries",
          "yAxis" = {
            "left" = {
              "showUnits" = false
            },
            "right" = {
              "showUnits" = false
            }
          },
          "region" = "${data.aws_region.current.name}",
          "title"  = "VPC Changes",
          "legend" = {
            "position" = "right"
          }
        }
      }
    ]
  })
}