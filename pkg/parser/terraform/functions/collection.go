package functions

import (
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

var (
	// ToSetFunc - https://developer.hashicorp.com/terraform/language/functions/toset
	ToSetFunc = stdlib.MakeToFunc(cty.Set(cty.DynamicPseudoType))
	// ToListFunc - https://developer.hashicorp.com/terraform/language/functions/tolist
	ToListFunc = stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType))
	// ToMapFunc - https://developer.hashicorp.com/terraform/language/functions/tomap
	ToMapFunc = stdlib.MakeToFunc(cty.Map(cty.DynamicPseudoType))
)
