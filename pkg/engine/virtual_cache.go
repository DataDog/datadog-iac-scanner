/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
// Adapted from OPA v1.13.2, v1/topdown/cache.go (Apache-2.0).
// Copyright 2017 The OPA Authors. All rights reserved.
package engine

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/util"
)

// identityVirtualCache is OPA's virtual cache (topdown.NewVirtualCache) with
// one change: a cached argument is first matched by identity. OPA memoizes
// function calls by their arguments and compares them by value, so a rule
// passing a whole document to a function, as in
//
//	some doc in input.document
//	f(doc, x)
//
// compared that document with itself in full on every call: on a plan with
// thousands of IAM resources, the privilege-escalation rules spent minutes
// each doing so. Identical terms are equal, so the cache returns what OPA's
// would.
type identityVirtualCache struct {
	stack []*identityVirtualCacheElem
}

type identityVirtualCacheElem struct {
	value     *ast.Term
	children  *util.HasherMap[*ast.Term, *identityVirtualCacheElem]
	undefined bool
}

func newIdentityVirtualCache() topdown.VirtualCache {
	cache := &identityVirtualCache{}
	cache.Push()
	return cache
}

func newIdentityVirtualCacheElem() *identityVirtualCacheElem {
	return &identityVirtualCacheElem{children: util.NewHasherMap[*ast.Term, *identityVirtualCacheElem](identicalOrEqualTerms)}
}

// identicalOrEqualTerms is ast.TermValueEqual, answering without a walk for
// the same term, object, array or set.
func identicalOrEqualTerms(a, b *ast.Term) bool {
	if a == b {
		return true
	}
	switch av := a.Value.(type) {
	case ast.Object:
		if bv, ok := b.Value.(ast.Object); ok && av == bv {
			return true
		}
	case *ast.Array:
		if bv, ok := b.Value.(*ast.Array); ok && av == bv {
			return true
		}
	case ast.Set:
		if bv, ok := b.Value.(ast.Set); ok && av == bv {
			return true
		}
	}
	return ast.TermValueEqual(a, b)
}

func (c *identityVirtualCache) Push() {
	c.stack = append(c.stack, newIdentityVirtualCacheElem())
}

func (c *identityVirtualCache) Pop() {
	c.stack = c.stack[:len(c.stack)-1]
}

func (c *identityVirtualCache) Get(ref ast.Ref) (*ast.Term, bool) {
	node := c.stack[len(c.stack)-1]
	for i := range ref {
		x, ok := node.children.Get(ref[i])
		if !ok {
			return nil, false
		}
		node = x
	}
	if node.undefined {
		return nil, true
	}
	return node.value, false
}

func (c *identityVirtualCache) Put(ref ast.Ref, value *ast.Term) {
	node := c.stack[len(c.stack)-1]
	for i := range ref {
		x, ok := node.children.Get(ref[i])
		if !ok {
			x = newIdentityVirtualCacheElem()
			node.children.Put(ref[i], x)
		}
		node = x
	}
	if value != nil {
		node.value = value
	} else {
		node.undefined = true
	}
}

func (c *identityVirtualCache) Keys() []ast.Ref {
	return identityVirtualCacheKeys(nil, c.stack[len(c.stack)-1])
}

func identityVirtualCacheKeys(root ast.Ref, node *identityVirtualCacheElem) []ast.Ref {
	var keys []ast.Ref
	node.children.Iter(func(k *ast.Term, v *identityVirtualCacheElem) bool {
		ref := root.Append(k)
		if v.value != nil {
			keys = append(keys, ref)
		}
		if v.children.Len() > 0 {
			keys = append(keys, identityVirtualCacheKeys(ref, v)...)
		}
		return false
	})
	return keys
}
