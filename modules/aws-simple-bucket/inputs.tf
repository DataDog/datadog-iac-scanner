variable "bucket_name" {
  description = "The name of the bucket"
  type        = string
}

variable "versioning_config" {
  description = "versioning configuration"
  type        = map(string)
  default     = {}
}
