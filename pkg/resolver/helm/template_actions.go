package helm

// replacement is a single pending text edit, collected before the edits are
// applied back to front.
type replacement struct {
	start int
	end   int
	text  string
}
