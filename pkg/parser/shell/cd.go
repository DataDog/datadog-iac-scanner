/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */
package shell

import "strings"

// cdOperand decodes the builtin's options without evaluating paths or shell
// state. An unresolved option/operand and OLDPWD expansion remain unknown.
func cdOperand(arguments []Value, dynamic bool) *Value {
	if dynamic {
		return &Value{}
	}
	options := true
	for i, argument := range arguments {
		if !argument.Known {
			return &argument
		}
		if options && argument.Text == "--" {
			options = false
			continue
		}
		if argument.Text == "-" {
			return &Value{Raw: argument.Text}
		}
		if options && strings.HasPrefix(argument.Text, "-") {
			if strings.Trim(argument.Text[1:], "LPe@") != "" {
				return &Value{Raw: argument.Text}
			}
			continue
		}
		if argument.Text == "" || i+1 < len(arguments) {
			return &Value{Raw: argument.Text}
		}
		return &argument
	}
	return nil
}
