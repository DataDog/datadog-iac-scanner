package helmaction

import (
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/Masterminds/sprig/v3"
)

// A resource name read from a template scanned as written holds its actions,
// "{{ $.Release.Name }}-worker", which is no name of anything deployed.
// ResolveName renders each action that only reads what is known of the
// release, and stands a placeholder for any other, naming what it reads:
// "<.Values.env>", "<randAlphaNum>", "<include app.fullname>".

// knownRoots are the fields of the template context a name can be rendered
// from when known.
var knownRoots = map[string]bool{"Release": true, "Chart": true}

// unsafeFuncs are not rendered: their output is not the template's, or they
// read what is outside it.
var unsafeFuncs = map[string]bool{
	"env": true, "expandenv": true, "getHostByName": true, "include": true, "template": true, "tpl": true,
	"lookup": true, "required": true, "fail": true, "now": true, "ago": true, "uuidv4": true,
	"randAlphaNum": true, "randAlpha": true, "randAscii": true, "randNumeric": true, "randBytes": true,
	"randInt": true, "shuffle": true, "bcrypt": true, "htpasswd": true, "encryptAES": true,
	"genPrivateKey": true, "genCA": true, "genCAWithKey": true, "genSelfSignedCert": true,
	"genSelfSignedCertWithKey": true, "genSignedCert": true, "genSignedCertWithKey": true,
}

// ResolveName returns name with each of its actions rendered from data when
// it reads nothing else, and replaced by a placeholder otherwise.
func ResolveName(name string, data map[string]interface{}) string {
	actions := Scan(name)
	if len(actions) == 0 {
		return name
	}
	var b strings.Builder
	last := 0
	for _, a := range actions {
		if a.Start < last {
			continue
		}
		b.WriteString(name[last:a.Start])
		last = a.End
		if a.Comment {
			continue
		}
		b.WriteString(resolveAction(actionCode(name[a.Start:a.End]), data))
	}
	b.WriteString(name[last:])
	return b.String()
}

// actionCode is the code of an action, without delimiters and trim markers.
func actionCode(action string) string {
	code := strings.TrimSuffix(strings.TrimPrefix(action, "{{"), "}}")
	if strings.HasPrefix(code, "- ") {
		code = code[1:]
	}
	if strings.HasSuffix(code, " -") {
		code = code[:len(code)-1]
	}
	return strings.TrimSpace(code)
}

func resolveAction(code string, data map[string]interface{}) string {
	tree := parse.New("name")
	tree.Mode = parse.SkipFuncCheck
	trees := map[string]*parse.Tree{}
	if _, err := tree.Parse("{{"+code+"}}", "", "", trees); err != nil || tree.Root == nil || len(tree.Root.Nodes) != 1 {
		// A variable declared outside the name does not parse on its own.
		if fields := strings.Fields(code); len(fields) > 0 && strings.HasPrefix(fields[0], "$") {
			label := fields[0]
			if strings.HasPrefix(label, "$.") {
				label = label[1:]
			}
			return "<" + label + ">"
		}
		return "<" + templateLabel + ">"
	}
	action, ok := tree.Root.Nodes[0].(*parse.ActionNode)
	if !ok || len(action.Pipe.Cmds) == 0 {
		return "<" + templateLabel + ">"
	}
	if renderable(action.Pipe, data) {
		funcs := sprig.TxtFuncMap()
		for f := range unsafeFuncs {
			delete(funcs, f)
		}
		t, err := template.New("name").Option("missingkey=error").Funcs(funcs).Parse("{{" + code + "}}")
		if err == nil {
			var out strings.Builder
			if t.Execute(&out, data) == nil && out.Len() > 0 {
				return out.String()
			}
		}
	}
	return "<" + actionLabel(action.Pipe.Cmds[0]) + ">"
}

// renderable reports whether a pipeline only reads known fields of data and
// calls no function whose output is not its own.
func renderable(pipe *parse.PipeNode, data map[string]interface{}) bool {
	ok := true
	var visit func(n parse.Node)
	visit = func(n parse.Node) {
		switch x := n.(type) {
		case *parse.PipeNode:
			if len(x.Decl) > 0 {
				ok = false
			}
			for _, c := range x.Cmds {
				visit(c)
			}
		case *parse.CommandNode:
			for _, a := range x.Args {
				visit(a)
			}
		case *parse.ChainNode:
			visit(x.Node)
		case *parse.IdentifierNode:
			ok = ok && !unsafeFuncs[x.Ident]
		case *parse.FieldNode:
			ok = ok && knownField(x.Ident, data)
		case *parse.VariableNode:
			ok = ok && x.Ident[0] == "$" && knownField(x.Ident[1:], data)
		case *parse.DotNode:
			ok = false
		}
	}
	visit(pipe)
	return ok
}

func knownField(path []string, data map[string]interface{}) bool {
	if len(path) == 0 || !knownRoots[path[0]] {
		return false
	}
	var cur interface{} = data
	for _, p := range path {
		m, isMap := cur.(map[string]interface{})
		if !isMap {
			return false
		}
		if cur, isMap = m[p]; !isMap {
			return false
		}
	}
	return true
}

// templateLabel names an action whose reads are not told apart.
const templateLabel = "template"

// actionLabel names what the first command of an action reads.
func actionLabel(cmd *parse.CommandNode) string {
	switch head := cmd.Args[0].(type) {
	case *parse.FieldNode:
		return head.String()
	case *parse.VariableNode:
		return variableLabel(head)
	case *parse.IdentifierNode:
		return callLabel(head.Ident, cmd.Args[1:])
	case *parse.PipeNode:
		if len(head.Cmds) > 0 {
			return actionLabel(head.Cmds[0])
		}
	}
	return templateLabel
}

// callLabel names a call of fn with args: the template an include renders,
// the value a printf or default formats, or else the function.
func callLabel(fn string, args []parse.Node) string {
	switch fn {
	case "include", templateLabel:
		if len(args) > 0 {
			if s, ok := args[0].(*parse.StringNode); ok {
				return fn + " " + s.Text
			}
		}
	case "printf", "print", "default":
		for _, a := range args {
			switch x := a.(type) {
			case *parse.FieldNode:
				return x.String()
			case *parse.VariableNode:
				return variableLabel(x)
			}
		}
	}
	return fn
}

// variableLabel names a variable read: a field of the template context as a
// field, "$.Values.env" as ".Values.env".
func variableLabel(v *parse.VariableNode) string {
	if v.Ident[0] == "$" && len(v.Ident) > 1 {
		return strings.TrimPrefix(v.String(), "$")
	}
	return v.String()
}
