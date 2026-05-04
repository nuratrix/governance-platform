variable "function_name" {
  type = string
}
variable "handler" {
  type = string
}
variable "role_arn" {
  type = string
}
variable "zip_path" {
  type = string
}
variable "zip_hash" {
  type = string
}
variable "timeout" {
  type    = number
  default = 60
}
variable "memory_size" {
  type    = number
  default = 256
}
variable "environment" {
  type    = map(string)
  default = {}
}
variable "enable_xray" {
  type    = bool
  default = true
}
variable "log_retention" {
  type    = number
  default = 30
}
