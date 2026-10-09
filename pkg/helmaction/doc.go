// Package helmaction finds the {{ ... }} actions of a Helm template source: where
// each one starts and ends, quoted strings and comments included, so the
// resolver rewrites templates and the runner blanks them with the same rules.
package helmaction
