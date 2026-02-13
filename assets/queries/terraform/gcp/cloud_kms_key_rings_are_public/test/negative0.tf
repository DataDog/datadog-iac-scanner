# IAM Member compliant
resource "google_kms_key_ring_iam_member" "good_example_member" {
  key_ring_id = "example-key-ring"
  member      = "user:someone@example.com" # ✅ Non-public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}


