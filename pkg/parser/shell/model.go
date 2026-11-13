package shell

// ParsedCommand represents a parsed shell command
type ParsedCommand struct {
	Type     string          `json:"type"`    // "command", "pipeline", "redirected_statement"
	Command  string          `json:"command"` // Command name (e.g., "echo", "cargo")
	Args     []ParsedArg     `json:"args"`    // Command arguments
	Redirect *ParsedRedirect `json:"redirect,omitempty"`
	Pipeline []ParsedCommand `json:"pipeline,omitempty"`
}

// ParsedArg represents a command argument
type ParsedArg struct {
	Type  string `json:"type"`          // "literal", "expansion", "command_substitution"
	Value string `json:"value"`         // The text content
	Var   string `json:"var,omitempty"` // Variable name if type is expansion
}

// ParsedRedirect represents a file redirection
type ParsedRedirect struct {
	Operator string    `json:"operator"` // ">>", ">", etc.
	Target   ParsedArg `json:"target"`   // Redirect target
}

// ParsedRun represents a fully parsed run block
type ParsedRun struct {
	Shell    string          `json:"shell"`           // "bash", "pwsh", etc.
	Commands []ParsedCommand `json:"commands"`        // All commands found
	ParseOK  bool            `json:"parse_ok"`        // Whether parsing succeeded
	Error    error           `json:"error,omitempty"` // Parse error if any
}
