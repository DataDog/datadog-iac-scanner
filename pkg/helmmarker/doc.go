// Package helmmarker owns the text the Helm resolver adds to templates and the
// resolver, runner and detector read back: the ID stamps that locate findings
// in a template, the invocation markers that record which action emitted a
// rendered document, and the one scanner that says where a template action
// starts and ends. Keeping them in a package of their own means a format
// changes in one place, and a consumer cannot drift from the writer.
package helmmarker
