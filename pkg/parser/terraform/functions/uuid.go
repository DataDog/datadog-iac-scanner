/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

var UUIDV5Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "namespace", Type: cty.String},
		{Name: "name", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		ns, err := uuidNamespace(args[0].AsString())
		if err != nil {
			return cty.NilVal, function.NewArgError(0, err)
		}
		return cty.StringVal(uuid.NewSHA1(ns, []byte(args[1].AsString())).String()), nil
	},
})

func uuidNamespace(s string) (uuid.UUID, error) {
	switch strings.ToLower(s) {
	case "dns":
		return uuid.NameSpaceDNS, nil
	case "url":
		return uuid.NameSpaceURL, nil
	case "oid":
		return uuid.NameSpaceOID, nil
	case "x500":
		return uuid.NameSpaceX500, nil
	default:
		ns, err := uuid.Parse(s)
		if err != nil {
			return uuid.Nil, fmt.Errorf("%q is not a named namespace or UUID", s)
		}
		return ns, nil
	}
}
