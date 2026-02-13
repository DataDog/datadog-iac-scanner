variable "bucket_name" {
  description = "The name of the bucket"
  type        = string
}

variable "enabled_versioning" {
  description = "versioning configuration"
  type        = bool
  default     = true
}
