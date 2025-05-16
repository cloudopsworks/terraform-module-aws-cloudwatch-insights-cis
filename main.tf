##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

data "aws_cloudwatch_log_group" "log_group" {
  name = var.settings.log_group_name
}

resource "aws_cloudformation_stack" "contributor_insights" {
  name = "CIS-Contributor-Insights"
  template_url = "https://raw.githubusercontent.com/aws-samples/aws-securityhub-remediations/refs/heads/main/aws-cis-contributorinsights/cft/CIS-ContributorInsights.yaml"
  parameters = {
    ContributorInsightRuleState = "ENABLED"
    CloudWatchLogGroup = "${data.aws_cloudwatch_log_group.log_group.name}"
  }
  tags = local.all_tags
}
