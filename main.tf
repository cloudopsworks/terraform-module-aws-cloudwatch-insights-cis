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
  template_body = file("${path.module}/cis-contributorinsights/CIS-Contributorinsights.yaml")
  parameters = {
    ContributorInsightRuleState = "ENABLED"
    CloudWatchLogGroupARN = data.aws_cloudwatch_log_group.log_group.arn
  }
  tags = local.all_tags
}
