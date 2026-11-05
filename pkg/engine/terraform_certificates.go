/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package engine

import (
	"context"
	"maps"

	"github.com/DataDog/datadog-iac-scanner/pkg/ctyutil"
	"github.com/DataDog/datadog-iac-scanner/pkg/model"
	"github.com/DataDog/datadog-iac-scanner/pkg/parser/utils"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// certificateBodyKey is the resource attribute holding a PEM certificate,
// which documents carry as what utils.CertificateInfo reads of it.
const certificateBodyKey = "certificate_body"

// parseCertificateBodies replaces every resource certificate_body of doc by
// what utils.CertificateInfo reads of the certificate: the body itself, as
// evaluated or planned, or, when path is the file the document is written
// in, the .pem file an unevaluated body names relative to it. Documents
// share subtrees, so the maps on the way to a body are copied rather than
// written to.
func parseCertificateBodies(ctx context.Context, doc model.Document, path string) {
	resources, ok := asStringMap(doc["resource"])
	if !ok {
		return
	}
	var parsedResources map[string]interface{}
	for typ, raw := range resources {
		blocks, ok := asStringMap(raw)
		if !ok {
			continue
		}
		var parsedBlocks map[string]interface{}
		for name, body := range blocks {
			fields, ok := asStringMap(body)
			if !ok {
				continue
			}
			info, read := certificateInfo(ctx, fields[certificateBodyKey], path)
			if info == nil {
				continue
			}
			if parsedBlocks == nil {
				parsedBlocks = maps.Clone(blocks)
			}
			fields = maps.Clone(fields)
			fields[certificateBodyKey] = info
			if read {
				forgetUnknown(fields, certificateBodyKey)
			}
			parsedBlocks[name] = fields
		}
		if parsedBlocks == nil {
			continue
		}
		if parsedResources == nil {
			parsedResources = maps.Clone(resources)
		}
		parsedResources[typ] = parsedBlocks
	}
	if parsedResources != nil {
		doc["resource"] = parsedResources
	}
}

// certificateInfo is what is read of the certificate body v holds or, with a
// path, names, which read reports; nil when v is neither.
func certificateInfo(ctx context.Context, v interface{}, path string) (info map[string]interface{}, read bool) {
	var body string
	switch value := v.(type) {
	case string:
		body = value
	case ctyjson.SimpleJSONValue:
		s, ok := ctyutil.ConcreteString(value.Value)
		if !ok {
			return nil, false
		}
		body = s
	default:
		return nil, false
	}
	if info, ok := utils.CertificateInfo(body); ok {
		return info, false
	}
	if path == "" {
		return nil, false
	}
	if file := utils.CheckCertificate(body); file != "" {
		info = utils.CertificateFileInfo(ctx, path, file)
	}
	return info, info != nil
}

// forgetUnknown drops attr from the _dd_meta.unknown of fields, a copy whose
// _dd_meta is shared with the block it was copied from.
func forgetUnknown(fields map[string]interface{}, attr string) {
	meta, ok := asStringMap(fields[ddMetaKey])
	if !ok {
		return
	}
	unknown, ok := asStringMap(meta[unknownKey])
	if !ok {
		return
	}
	if _, ok := unknown[attr]; !ok {
		return
	}
	meta, unknown = maps.Clone(meta), maps.Clone(unknown)
	delete(unknown, attr)
	if len(unknown) == 0 {
		delete(meta, unknownKey)
	} else {
		meta[unknownKey] = unknown
	}
	fields[ddMetaKey] = meta
}
