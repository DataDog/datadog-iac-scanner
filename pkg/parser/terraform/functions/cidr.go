/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package functions

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/gocty"
)

var CidrHostFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "prefix", Type: cty.String},
		{Name: "hostnum", Type: cty.Number},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		prefix, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		var hostNum big.Int
		if err := gocty.FromCtyValue(args[1], &hostNum); err != nil {
			return cty.NilVal, function.NewArgError(1, err)
		}
		addr, err := cidrHost(prefix, &hostNum)
		if err != nil {
			return cty.NilVal, err
		}
		return cty.StringVal(addr.String()), nil
	},
})

var CidrNetmaskFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "prefix",
		Type: cty.String,
	}},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		prefix, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		if !prefix.Addr().Is4() {
			return cty.NilVal, function.NewArgErrorf(0, "cidrnetmask only supports IPv4")
		}
		mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
		return cty.StringVal(net.IP(mask).String()), nil
	},
})

var CidrSubnetFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "prefix", Type: cty.String},
		{Name: "newbits", Type: cty.Number},
		{Name: "netnum", Type: cty.Number},
	},
	Type: function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		prefix, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		var newbits int
		var netnum big.Int
		if err := gocty.FromCtyValue(args[1], &newbits); err != nil {
			return cty.NilVal, function.NewArgError(1, err)
		}
		if err := gocty.FromCtyValue(args[2], &netnum); err != nil {
			return cty.NilVal, function.NewArgError(2, err)
		}
		out, err := cidrSubnet(prefix, newbits, &netnum)
		if err != nil {
			return cty.NilVal, err
		}
		return cty.StringVal(out.String()), nil
	},
})

var CidrSubnetsFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name: "prefix",
		Type: cty.String,
	}},
	VarParam: &function.Parameter{
		Name: "newbits",
		Type: cty.Number,
	},
	Type: function.StaticReturnType(cty.List(cty.String)),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		prefix, err := parsePrefix(args[0].AsString())
		if err != nil {
			return cty.NilVal, err
		}
		if len(args) == 1 {
			return cty.ListValEmpty(cty.String), nil
		}
		newbits := make([]int, len(args)-1)
		for i, arg := range args[1:] {
			if err := gocty.FromCtyValue(arg, &newbits[i]); err != nil {
				return cty.NilVal, function.NewArgError(i+1, err)
			}
		}
		subs, err := cidrSubnets(prefix, newbits)
		if err != nil {
			return cty.NilVal, err
		}
		vals := make([]cty.Value, len(subs))
		for i, sub := range subs {
			vals[i] = cty.StringVal(sub)
		}
		return cty.ListVal(vals), nil
	},
})

func parsePrefix(s string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, function.NewArgErrorf(0, "invalid CIDR prefix: %s", err)
	}
	return prefix, nil
}

func cidrHost(prefix netip.Prefix, hostNum *big.Int) (netip.Addr, error) {
	base := prefixToInt(prefix.Masked())
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	maxHosts := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	n := new(big.Int).Set(hostNum)
	if n.Sign() < 0 {
		n.Add(n, maxHosts)
	}
	if n.Sign() < 0 || n.Cmp(maxHosts) >= 0 {
		return netip.Addr{}, fmt.Errorf("host number %s is out of range for %s", hostNum, prefix)
	}
	return intToAddr(base.Add(base, n), prefix.Addr().Is4())
}

func cidrSubnet(prefix netip.Prefix, newbits int, netnum *big.Int) (netip.Prefix, error) {
	if newbits < 0 {
		return netip.Prefix{}, function.NewArgErrorf(1, "newbits must be non-negative")
	}
	newLen := prefix.Bits() + newbits
	bitLen := prefix.Addr().BitLen()
	if newLen > bitLen {
		return netip.Prefix{}, fmt.Errorf("not enough remaining address space after prefix of %d bits", prefix.Bits())
	}
	maxNets := new(big.Int).Lsh(big.NewInt(1), uint(newbits))
	if netnum.Sign() < 0 || netnum.Cmp(maxNets) >= 0 {
		return netip.Prefix{}, fmt.Errorf("netnum %s is out of range", netnum)
	}
	step := new(big.Int).Lsh(big.NewInt(1), uint(bitLen-newLen))
	base := prefixToInt(prefix.Masked())
	base.Add(base, new(big.Int).Mul(step, netnum))
	addr, err := intToAddr(base, prefix.Addr().Is4())
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, newLen), nil
}

func cidrSubnets(prefix netip.Prefix, newbits []int) ([]string, error) {
	bitLen := prefix.Addr().BitLen()
	start := prefixToInt(prefix.Masked())
	end := new(big.Int).Add(prefixToInt(prefix.Masked()), new(big.Int).Lsh(big.NewInt(1), uint(bitLen-prefix.Bits())))
	out := make([]string, 0, len(newbits))
	for _, nb := range newbits {
		if nb < 1 {
			return nil, fmt.Errorf("must extend prefix by at least one bit")
		}
		newLen := prefix.Bits() + nb
		if newLen > bitLen {
			return nil, fmt.Errorf("not enough remaining address space after prefix of %d bits", prefix.Bits())
		}
		step := new(big.Int).Lsh(big.NewInt(1), uint(bitLen-newLen))
		// After a smaller block, skip ahead to the next prefix-aligned start.
		start = alignUp(start, step)
		next := new(big.Int).Add(start, step)
		if next.Cmp(end) > 0 {
			return nil, fmt.Errorf("not enough remaining address space to allocate /%d", newLen)
		}
		addr, err := intToAddr(new(big.Int).Set(start), prefix.Addr().Is4())
		if err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s/%d", addr, newLen))
		start = next
	}
	return out, nil
}

func alignUp(n, step *big.Int) *big.Int {
	rem := new(big.Int).Mod(n, step)
	if rem.Sign() == 0 {
		return n
	}
	return new(big.Int).Add(n, new(big.Int).Sub(step, rem))
}

func prefixToInt(prefix netip.Prefix) *big.Int {
	return new(big.Int).SetBytes(prefix.Addr().AsSlice())
}

func intToAddr(n *big.Int, ipv4 bool) (netip.Addr, error) {
	size := 16
	if ipv4 {
		size = 4
	}
	b := n.Bytes()
	if len(b) > size {
		return netip.Addr{}, fmt.Errorf("address overflow")
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	addr, ok := netip.AddrFromSlice(padded)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid address")
	}
	return addr, nil
}
