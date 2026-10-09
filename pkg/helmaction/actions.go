package helmaction

import (
	"sort"
	"strings"
)

// Action is one {{ ... }} template action of a template source, as byte offsets.
type Action struct {
	Start, End int
	// Comment is a {{/* ... */}} action.
	Comment bool
	// Unterminated actions have no closing "}}" outside quotes. They end after
	// the next "}}", or at the end of the source when there is none.
	Unterminated bool
}

// Scan returns every action of s in order of start. Quoted strings (", ' and `)
// are opaque, so a "}}" inside one does not end an action. A comment ends at
// its "*/" followed by "}}", as its text may hold quotes of its own. Scanning
// resumes just after the "{{" of an unterminated action, so the actions after
// it are still found, and may lie within it.
func Scan(s string) []Action {
	var actions []Action
	for i := 0; i+1 < len(s); {
		start := strings.Index(s[i:], "{{")
		if start < 0 {
			break
		}
		start += i
		action := Action{Start: start}
		if c := commentStart(s, start); c >= 0 {
			action.Comment = true
			action.End, action.Unterminated = commentEnd(s, c)
		} else {
			action.End, _, action.Unterminated = scanAction(s, start, len(s))
		}
		if action.Unterminated {
			action.End = len(s)
			if next := strings.Index(s[start+2:], "}}"); next >= 0 {
				action.End = start + 2 + next + 2
			}
			i = start + 2
		} else {
			i = action.End
		}
		actions = append(actions, action)
	}
	return actions
}

// Terminated returns the actions of s that have a closing "}}".
func Terminated(s string) []Action {
	actions := Scan(s)
	kept := actions[:0]
	for _, a := range actions {
		if !a.Unterminated {
			kept = append(kept, a)
		}
	}
	return kept
}

// Code returns the terminated actions of s that are not comments.
func Code(s string) []Action {
	actions := Terminated(s)
	kept := actions[:0]
	for _, a := range actions {
		if !a.Comment {
			kept = append(kept, a)
		}
	}
	return kept
}

// Remove drops every terminated action from s.
func Remove(s string) string {
	var b strings.Builder
	last := 0
	for _, a := range Terminated(s) {
		b.WriteString(s[last:a.Start])
		last = a.End
	}
	b.WriteString(s[last:])
	return b.String()
}

// Blank replaces every action of source with the newlines it spanned, an
// unterminated one included, so the line numbers of what remains are unchanged.
func Blank(source []byte) []byte {
	s := string(source)
	var b strings.Builder
	last := 0
	for _, a := range Scan(s) {
		from := max(a.Start, last)
		if a.End <= from {
			continue
		}
		b.WriteString(s[last:from])
		b.WriteString(strings.Repeat("\n", strings.Count(s[from:a.End], "\n")))
		last = a.End
	}
	b.WriteString(s[last:])
	return []byte(b.String())
}

// find returns the action containing pos, which actions must be sorted and
// non-overlapping for.
func find(pos int, actions []Action) (Action, bool) {
	i := sort.Search(len(actions), func(i int) bool { return actions[i].Start > pos })
	if i == 0 || pos >= actions[i-1].End {
		return Action{}, false
	}
	return actions[i-1], true
}

// InAny reports whether pos falls within one of actions.
func InAny(pos int, actions []Action) bool {
	_, ok := find(pos, actions)
	return ok
}

// InQuote reports whether pos is inside a quoted string of the action of
// actions that contains it.
func InQuote(s string, pos int, actions []Action) bool {
	a, ok := find(pos, actions)
	if !ok || a.Comment {
		return false
	}
	_, quote, _ := scanAction(s, a.Start, pos)
	return quote != 0
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// commentStart returns the index of the "/*" opening the comment action whose
// "{{" is at start, or -1 when the action is not a comment.
func commentStart(s string, start int) int {
	c := start + 2
	if c < len(s) && s[c] == '-' {
		c++
	}
	for c < len(s) && isSpace(s[c]) {
		c++
	}
	if c+1 < len(s) && s[c] == '/' && s[c+1] == '*' {
		return c
	}
	return -1
}

// commentEnd returns the end of the comment action whose "/*" is at start: the
// first "*/", then optional whitespace, a trim marker and "}}".
func commentEnd(s string, start int) (end int, unterminated bool) {
	closeIdx := strings.Index(s[start+2:], "*/")
	if closeIdx < 0 {
		return 0, true
	}
	c := start + 2 + closeIdx + 2
	for c < len(s) && isSpace(s[c]) {
		c++
	}
	if c < len(s) && s[c] == '-' {
		c++
	}
	if c+1 < len(s) && s[c] == '}' && s[c+1] == '}' {
		return c + 2, false
	}
	return 0, true
}

// scanAction walks the action whose "{{" is at start up to stop, tracking
// quoted strings. It returns the end of the action when its "}}" lies before
// stop, and otherwise the quote open at stop (0 for none).
func scanAction(s string, start, stop int) (end int, quote byte, unterminated bool) {
	for i := start + 2; i < stop; i++ {
		c := s[i]
		switch {
		case quote == '`':
			if c == '`' {
				quote = 0
			}
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '}' && i+1 < len(s) && s[i+1] == '}':
			return i + 2, 0, false
		}
	}
	return 0, quote, true
}
