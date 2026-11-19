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
