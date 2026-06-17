package tfeval

import (
	"context"
	"testing"
)

func TestForEachEmptyStringKeyCrossRef(t *testing.T) {
	root := t.TempDir()
	// A plain resource references the empty-key instance via aws_s3_bucket.b[""].bucket
	dir := writeModule(t, root, "mod", map[string]string{
		"main.tf": `
resource "aws_s3_bucket" "b" {
  for_each = { "" = "val-empty" }
  bucket   = each.value
}

resource "aws_iam_policy" "p" {
  name = aws_s3_bucket.b[""].bucket
}
`,
	})
	resources, _, _, err := New().EvaluateModule(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("EvaluateModule: %v", err)
	}
	r := findResource(t, resources, "aws_iam_policy", "p")
	requireString(t, r.Attributes, "name", "val-empty")
}
