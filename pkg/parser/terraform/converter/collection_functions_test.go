package converter_test

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/terraform/converter"
	"github.com/hashicorp/hcl/v2/hclparse"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

func TestTosetForEachInDynamicBlock(t *testing.T) {
	src := []byte(`resource "google_sql_database_instance" "x" {
  settings {
    dynamic "ip_configuration" {
      for_each = toset(["private"])
      content {
        ipv4_enabled = false
        private_network = "net"
      }
    }
  }
}`)
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, "test.tf")
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	doc, err := converter.DefaultConverted(context.Background(), file, nil)
	if err != nil {
		t.Fatal(err)
	}
	resource := doc["resource"].(model.Document)["google_sql_database_instance"].(model.Document)["x"].(model.Document)
	settings := resource["settings"].(model.Document)
	if _, ok := settings["dynamic"]; ok {
		t.Fatal("dynamic block was not expanded")
	}
	ipConfiguration, ok := settings["ip_configuration"].(model.Document)
	if !ok {
		t.Fatalf("ip_configuration = %#v, want the single block toset([\"private\"]) generates", settings["ip_configuration"])
	}
	ipv4, ok := ipConfiguration["ipv4_enabled"].(ctyjson.SimpleJSONValue)
	if !ok || ipv4.Value.True() {
		t.Fatalf("ipv4_enabled = %#v, want false", ipConfiguration["ipv4_enabled"])
	}
}
