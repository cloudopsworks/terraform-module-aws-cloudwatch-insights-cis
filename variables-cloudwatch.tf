##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

# YAML sample for module inputs
# settings:
#   exclude:
#     unauthorized_events:
#       - "CreateUser"
#       - "DeleteUser"
#     unauthorized_sources:
#     - "macie2.amazonaws.com"
#     - "cloud9.amazonaws.com"
#   log_group_name: "/aws/lambda/my-function"

variable "settings" {
  description = "Settings for the insights"
  type        = any
  default     = {}
}