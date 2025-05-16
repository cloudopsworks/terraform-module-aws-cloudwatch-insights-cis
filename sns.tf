##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

resource "aws_sns_topic" "cis_alarm_topic" {
  name         = "cis-alarm-${local.system_name}-topic"
  display_name = "CIS Foundation Metrics Alarm Topic"
  tags         = local.all_tags
}