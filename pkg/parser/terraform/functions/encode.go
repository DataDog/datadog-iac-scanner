/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"  //nolint:gosec // Terraform md5()
	"crypto/sha1" //nolint:gosec // Terraform sha1()
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"golang.org/x/text/encoding/ianaindex"
)

var Base64DecodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "str",
		Type: cty.String,
	}},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		s := args[0].AsString()
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return cty.NilVal, function.NewArgErrorf(0, "invalid base64: %s", err)
			}
		}
		if !utf8.Valid(decoded) {
			return cty.NilVal, function.NewArgErrorf(0, "the result of decoding the provided string is not valid UTF-8")
		}
		return cty.StringVal(string(decoded)), nil
	},
})

var URLEncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "str",
		Type: cty.String,
	}},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(url.QueryEscape(args[0].AsString())), nil
	},
})

func hashHexFunc(newHash func() hash.Hash) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{
			Name: "str",
			Type: cty.String,
		}},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			h := newHash()
			_, _ = h.Write([]byte(args[0].AsString()))
			return cty.StringVal(hex.EncodeToString(h.Sum(nil))), nil
		},
	})
}

func hashBase64Func(newHash func() hash.Hash) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{
			Name: "str",
			Type: cty.String,
		}},
		Type: function.StaticReturnType(cty.String),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			h := newHash()
			_, _ = h.Write([]byte(args[0].AsString()))
			return cty.StringVal(base64.StdEncoding.EncodeToString(h.Sum(nil))), nil
		},
	})
}

var (
	Md5Func          = hashHexFunc(md5.New)
	Sha1Func         = hashHexFunc(sha1.New)
	Sha256Func       = hashHexFunc(sha256.New)
	Sha512Func       = hashHexFunc(sha512.New)
	Base64Sha256Func = hashBase64Func(sha256.New)
	Base64Sha512Func = hashBase64Func(sha512.New)
)

var Base64GzipFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.ModTime = time.Unix(0, 0)
		if _, err := gz.Write([]byte(args[0].AsString())); err != nil {
			return cty.NilVal, err
		}
		if err := gz.Close(); err != nil {
			return cty.NilVal, err
		}
		return cty.StringVal(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
	},
})

var TextEncodeBase64Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "string", Type: cty.String},
		{Name: "encoding", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		enc, err := ianaindex.IANA.Encoding(args[1].AsString())
		if err != nil || enc == nil {
			return cty.NilVal, function.NewArgErrorf(1, "%q is not a supported IANA encoding name", args[1].AsString())
		}
		encoded, err := enc.NewEncoder().Bytes([]byte(args[0].AsString()))
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(0, "the given string cannot be represented in %s", args[1].AsString())
		}
		return cty.StringVal(base64.StdEncoding.EncodeToString(encoded)), nil
	},
})

var TextDecodeBase64Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "source", Type: cty.String},
		{Name: "encoding", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		enc, err := ianaindex.IANA.Encoding(args[1].AsString())
		if err != nil || enc == nil {
			return cty.NilVal, function.NewArgErrorf(1, "%q is not a supported IANA encoding name", args[1].AsString())
		}
		raw, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgErrorf(0, "invalid base64: %s", err)
		}
		decoded, err := enc.NewDecoder().Bytes(raw)
		if err != nil || bytes.ContainsRune(decoded, '�') {
			return cty.NilVal, function.NewArgErrorf(0, "the given string contains symbols that are not defined for %s", args[1].AsString())
		}
		return cty.StringVal(string(decoded)), nil
	},
})
