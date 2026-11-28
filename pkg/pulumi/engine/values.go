/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

package engine

import (
	"math"
	"strings"

	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"google.golang.org/protobuf/types/known/structpb"
)

// Pulumi wire-format signatures, from github.com/pulumi/pulumi/sdk/v3/go/common/resource/sig.
const (
	sigKey         = "4dabf18193072939515e22adb298388d"
	sigSecret      = "1b47061264138c4ac30d75fd1eb44270"
	sigResourceRef = "5cf8f73096256a8f31e491e813e4eb8e"
	sigOutputValue = "d0e6a833031e9bbcd3f4e8bde6ca49a4"
	sigAsset       = "c44067f5952c0a294b673a41bacd8c17"
	sigArchive     = "0def7320c3a5731c473e5ecbe6d01bc7"
)

// unknownString is the sentinel the SDKs send for a value that is not known
// before deployment. The engine also defines typed variants; accept them all.
const unknownString = "04da6b54-80e4-46f7-96ec-b56ff0331ba9"

var unknownSentinels = map[string]bool{
	unknownString:                          true,
	"1c4a061d-8072-4f0a-a4cb-0ff528b18fe7": true, // bool
	"3eeb2bf0-c639-47a8-9e75-3b44932eb421": true, // number
	"6a19a0b0-7e62-4c92-b797-7f8e31da9cc2": true, // array
	"030794c1-ac77-496b-92df-f27374a8bd58": true, // asset
	"e48ece36-62e2-4504-bad9-02848725956a": true, // archive
	"dd056dcd-154b-4c76-9bd3-c8f88648b5ff": true, // object
}

func unknownMarker() map[string]any { return map[string]any{capture.MarkerUnknown: true} }

// decodeStruct turns a Pulumi property map into plain JSON values with the
// capture markers for unknown values, secrets, resource references, assets and
// archives.
func decodeStruct(s *structpb.Struct) map[string]any {
	out := make(map[string]any, len(s.GetFields()))
	for k, v := range s.GetFields() {
		out[k] = decode(v)
	}
	return out
}

func decode(v *structpb.Value) any {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		if unknownSentinels[k.StringValue] {
			return unknownMarker()
		}
		return k.StringValue
	case *structpb.Value_NumberValue:
		// JSON has no NaN or infinity: such a number is recorded as unknown so
		// that the capture stays encodable.
		if math.IsNaN(k.NumberValue) || math.IsInf(k.NumberValue, 0) {
			return unknownMarker()
		}
		return k.NumberValue
	case *structpb.Value_ListValue:
		out := make([]any, 0, len(k.ListValue.GetValues()))
		for _, e := range k.ListValue.GetValues() {
			out = append(out, decode(e))
		}
		return out
	case *structpb.Value_StructValue:
		return decodeObject(k.StructValue)
	case nil:
		return nil
	default:
		return v.AsInterface()
	}
}

func decodeObject(s *structpb.Struct) any {
	f := s.GetFields()
	sig, ok := f[sigKey]
	if !ok {
		return decodeStruct(s)
	}
	switch sig.GetStringValue() {
	case sigSecret:
		return map[string]any{capture.MarkerSecret: true}
	case sigOutputValue:
		if f["secret"].GetBoolValue() {
			return map[string]any{capture.MarkerSecret: true}
		}
		if val, known := f["value"]; known {
			return decode(val)
		}
		return unknownMarker()
	case sigResourceRef:
		return map[string]any{capture.MarkerResourceRef: f["urn"].GetStringValue()}
	case sigAsset:
		return assetMarker(capture.MarkerAsset, f)
	case sigArchive:
		return assetMarker(capture.MarkerArchive, f)
	default:
		return decodeStruct(s)
	}
}

// assetMarker keeps where an asset or archive comes from, never its content.
func assetMarker(marker string, f map[string]*structpb.Value) map[string]any {
	out := map[string]any{marker: true}
	for _, k := range []string{"path", "uri"} {
		if s := f[k].GetStringValue(); s != "" {
			out[k] = s
		}
	}
	return out
}

// isPlain reports whether a decoded value carries no capture marker.
func isPlain(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if strings.HasPrefix(k, "__dd_") || !isPlain(e) {
				return false
			}
		}
	case []any:
		for _, e := range t {
			if !isPlain(e) {
				return false
			}
		}
	}
	return true
}
