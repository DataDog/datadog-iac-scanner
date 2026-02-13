# IAM Binding compliant
resource "google_kms_key_ring_iam_binding" "good_example_binding" {
  key_ring_id = "example-key-ring"
  members     = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}
