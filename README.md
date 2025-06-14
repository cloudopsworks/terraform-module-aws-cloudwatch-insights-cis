<!-- 
  ** DO NOT EDIT THIS FILE
  ** 
  ** This file was automatically generated. 
  ** 1) Make all changes to `README.yaml` 
  ** 2) Run `make init` (you only need to do this once)
  ** 3) Run`make readme` to rebuild this file. 
  -->
[![README Header][readme_header_img]][readme_header_link]

[![cloudopsworks][logo]](https://cloudops.works/)

# Terraform AWS CIS CloudWatch Insights Module




This Terraform module provides a comprehensive setup for AWS CloudWatch Insights with CIS compliance rules. 
It includes configurations for CloudWatch log groups, exclusion rules, and insights rules to monitor AWS resources effectively. 
The module is designed to enhance security and compliance monitoring across AWS accounts.


---

This project is part of our comprehensive approach towards DevOps Acceleration. 
[<img align="right" title="Share via Email" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/ios-mail.svg"/>][share_email]
[<img align="right" title="Share on Google+" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/logo-googleplus.svg" />][share_googleplus]
[<img align="right" title="Share on Facebook" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/logo-facebook.svg" />][share_facebook]
[<img align="right" title="Share on Reddit" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/logo-reddit.svg" />][share_reddit]
[<img align="right" title="Share on LinkedIn" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/logo-linkedin.svg" />][share_linkedin]
[<img align="right" title="Share on Twitter" width="24" height="24" src="https://docs.cloudops.works/images/ionicons/logo-twitter.svg" />][share_twitter]


[![Terraform Open Source Modules](https://docs.cloudops.works/images/terraform-open-source-modules.svg)][terraform_modules]



It's 100% Open Source and licensed under the [APACHE2](LICENSE).







We have [*lots of terraform modules*][terraform_modules] that are Open Source and we are trying to get them well-maintained!. Check them out!






## Introduction

This Terraform module facilitates the setup and configuration of AWS Transit Gateway with Resource Access Manager (RAM) support. 
It enables centralized management of VPC connectivity across multiple AWS accounts and regions, with built-in CloudWatch monitoring 
and alerting capabilities. The module includes CIS compliance monitoring dashboard and comprehensive insights rules for security tracking.

## Usage


**IMPORTANT:** The `master` branch is used in `source` just as an example. In your code, do not pin to `master` because there may be breaking changes between releases.
Instead pin to the release tag (e.g. `?ref=vX.Y.Z`) of one of our [latest releases](https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis/releases).


1. Configure your AWS credentials and region
2. Include this module in your Terraform configuration
3. Configure the required variables:
   - settings: Configure CloudWatch log group and exclusion rules
   - Additional AWS-specific configurations as needed
4. Apply the configuration using Terraform workflow

## Quick Start

1. Clone the repository:
   git clone https://github.com/cloudopsworks/terraform-module-aws-vpc-setup.git

2. Create a terragrunt.hcl file with basic configuration:
   ```hcl
   terraform {
     source = "git::https://github.com/cloudopsworks/terraform-module-aws-vpc-setup.git?ref=v1.0.0"
   }

   inputs = {
     settings = {
       log_group_name = "/aws/transit-gateway/logs"
     }
   }
   ```

3. Initialize and apply:
   terragrunt init
   terragrunt plan
   terragrunt apply


## Examples

```hcl
# Terragrunt configuration example
terraform {
  source = "git::https://github.com/cloudopsworks/terraform-module-aws-vpc-setup.git?ref=v1.0.0"
}

inputs = {
  settings = {
    log_group_name = "/aws/transit-gateway/logs"
    exclude = {
      unauthorized_events = ["CreateUser", "DeleteUser"]
      unauthorized_sources = ["macie2.amazonaws.com", "cloud9.amazonaws.com"]
    }
  }
}
```



## Makefile Targets
```
Available targets:

  help                                Help screen
  help/all                            Display help for all targets
  help/short                          This help short screen
  lint                                Lint terraform/opentofu code
  tag                                 Tag the current version

```
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.97.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_tags"></a> [tags](#module\_tags) | cloudopsworks/tags/local | 1.0.9 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_contributor_insight_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_contributor_insight_rule) | resource |
| [aws_cloudwatch_dashboard.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_dashboard) | resource |
| [aws_cloudwatch_metric_alarm.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_sns_topic.cis_alarm_topic](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_cloudwatch_log_group.log_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/cloudwatch_log_group) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_extra_tags"></a> [extra\_tags](#input\_extra\_tags) | Extra tags to add to the resources | `map(string)` | `{}` | no |
| <a name="input_is_hub"></a> [is\_hub](#input\_is\_hub) | Is this a hub or spoke configuration? | `bool` | `false` | no |
| <a name="input_org"></a> [org](#input\_org) | Organization details | <pre>object({<br/>    organization_name = string<br/>    organization_unit = string<br/>    environment_type  = string<br/>    environment_name  = string<br/>  })</pre> | n/a | yes |
| <a name="input_settings"></a> [settings](#input\_settings) | Settings for the insights | `any` | `{}` | no |
| <a name="input_spoke_def"></a> [spoke\_def](#input\_spoke\_def) | Spoke ID Number, must be a 3 digit number | `string` | `"001"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cis_bucket_policy_changes_alarm_arn"></a> [cis\_bucket\_policy\_changes\_alarm\_arn](#output\_cis\_bucket\_policy\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_cloudtrail_configuration_changes_alarm_arn"></a> [cis\_cloudtrail\_configuration\_changes\_alarm\_arn](#output\_cis\_cloudtrail\_configuration\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_cmk_deletion_disabling_alarm_arn"></a> [cis\_cmk\_deletion\_disabling\_alarm\_arn](#output\_cis\_cmk\_deletion\_disabling\_alarm\_arn) | n/a |
| <a name="output_cis_config_configuration_changes_alarm_arn"></a> [cis\_config\_configuration\_changes\_alarm\_arn](#output\_cis\_config\_configuration\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_console_authentication_failures_alarm_arn"></a> [cis\_console\_authentication\_failures\_alarm\_arn](#output\_cis\_console\_authentication\_failures\_alarm\_arn) | n/a |
| <a name="output_cis_console_signin_without_mfa_alarm_arn"></a> [cis\_console\_signin\_without\_mfa\_alarm\_arn](#output\_cis\_console\_signin\_without\_mfa\_alarm\_arn) | n/a |
| <a name="output_cis_iam_changes_alarm_arn"></a> [cis\_iam\_changes\_alarm\_arn](#output\_cis\_iam\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_network_acl_changes_alarm_arn"></a> [cis\_network\_acl\_changes\_alarm\_arn](#output\_cis\_network\_acl\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_root_activity_alarm_arn"></a> [cis\_root\_activity\_alarm\_arn](#output\_cis\_root\_activity\_alarm\_arn) | n/a |
| <a name="output_cis_route_table_changes_alarm_arn"></a> [cis\_route\_table\_changes\_alarm\_arn](#output\_cis\_route\_table\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_security_group_changes_alarm_arn"></a> [cis\_security\_group\_changes\_alarm\_arn](#output\_cis\_security\_group\_changes\_alarm\_arn) | n/a |
| <a name="output_cis_sns_topic_arn"></a> [cis\_sns\_topic\_arn](#output\_cis\_sns\_topic\_arn) | n/a |
| <a name="output_cis_sns_topic_name"></a> [cis\_sns\_topic\_name](#output\_cis\_sns\_topic\_name) | n/a |
| <a name="output_cis_unauthorized_api_activity_alarm_arn"></a> [cis\_unauthorized\_api\_activity\_alarm\_arn](#output\_cis\_unauthorized\_api\_activity\_alarm\_arn) | n/a |
| <a name="output_cis_vpc_changes_alarm_arn"></a> [cis\_vpc\_changes\_alarm\_arn](#output\_cis\_vpc\_changes\_alarm\_arn) | n/a |



## Help

**Got a question?** We got answers. 

File a GitHub [issue](https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis/issues), send us an [email][email] or join our [Slack Community][slack].

[![README Commercial Support][readme_commercial_support_img]][readme_commercial_support_link]

## DevOps Tools

## Slack Community


## Newsletter

## Office Hours

## Contributing

### Bug Reports & Feature Requests

Please use the [issue tracker](https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis/issues) to report any bugs or file feature requests.

### Developing




## Copyrights

Copyright © 2024-2025 [Cloud Ops Works LLC](https://cloudops.works)





## License 

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

See [LICENSE](LICENSE) for full details.

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.









## Trademarks

All other trademarks referenced herein are the property of their respective owners.

## About

This project is maintained by [Cloud Ops Works LLC][website]. 


### Contributors

|  [![Cristian Beraha][berahac_avatar]][berahac_homepage]<br/>[Cristian Beraha][berahac_homepage] |
|---|

  [berahac_homepage]: https://github.com/berahac
  [berahac_avatar]: https://github.com/berahac.png?size=50

[![README Footer][readme_footer_img]][readme_footer_link]
[![Beacon][beacon]][website]

  [logo]: https://cloudops.works/logo-300x69.svg
  [docs]: https://cowk.io/docs?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=docs
  [website]: https://cowk.io/homepage?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=website
  [github]: https://cowk.io/github?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=github
  [jobs]: https://cowk.io/jobs?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=jobs
  [hire]: https://cowk.io/hire?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=hire
  [slack]: https://cowk.io/slack?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=slack
  [linkedin]: https://cowk.io/linkedin?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=linkedin
  [twitter]: https://cowk.io/twitter?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=twitter
  [testimonial]: https://cowk.io/leave-testimonial?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=testimonial
  [office_hours]: https://cloudops.works/office-hours?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=office_hours
  [newsletter]: https://cowk.io/newsletter?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=newsletter
  [email]: https://cowk.io/email?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=email
  [commercial_support]: https://cowk.io/commercial-support?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=commercial_support
  [we_love_open_source]: https://cowk.io/we-love-open-source?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=we_love_open_source
  [terraform_modules]: https://cowk.io/terraform-modules?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=terraform_modules
  [readme_header_img]: https://cloudops.works/readme/header/img
  [readme_header_link]: https://cloudops.works/readme/header/link?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=readme_header_link
  [readme_footer_img]: https://cloudops.works/readme/footer/img
  [readme_footer_link]: https://cloudops.works/readme/footer/link?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=readme_footer_link
  [readme_commercial_support_img]: https://cloudops.works/readme/commercial-support/img
  [readme_commercial_support_link]: https://cloudops.works/readme/commercial-support/link?utm_source=github&utm_medium=readme&utm_campaign=cloudopsworks/terraform-module-aws-cloudwatch-insights-cis&utm_content=readme_commercial_support_link
  [share_twitter]: https://twitter.com/intent/tweet/?text=Terraform+AWS+CIS+CloudWatch+Insights+Module&url=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [share_linkedin]: https://www.linkedin.com/shareArticle?mini=true&title=Terraform+AWS+CIS+CloudWatch+Insights+Module&url=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [share_reddit]: https://reddit.com/submit/?url=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [share_facebook]: https://facebook.com/sharer/sharer.php?u=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [share_googleplus]: https://plus.google.com/share?url=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [share_email]: mailto:?subject=Terraform+AWS+CIS+CloudWatch+Insights+Module&body=https://github.com/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis
  [beacon]: https://ga-beacon.cloudops.works/G-7XWMFVFXZT/cloudopsworks/terraform-module-aws-cloudwatch-insights-cis?pixel&cs=github&cm=readme&an=terraform-module-aws-cloudwatch-insights-cis
