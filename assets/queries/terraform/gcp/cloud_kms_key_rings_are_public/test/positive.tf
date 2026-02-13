# IAM Member violation
resource "google_kms_key_ring_iam_member" "bad_example_member" {
  key_ring_id = "example-key-ring"
  member      = "allUsers" # ❌ Public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}

# IAM Binding violation
resource "google_kms_key_ring_iam_binding" "bad_example_binding" {
  key_ring_id = "example-key-ring"
  members     = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}
