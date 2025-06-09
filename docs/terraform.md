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
