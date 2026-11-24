package docker

// newTestScope returns a scope whose variables are already declared, as if by
// ARG instructions with these literal values.
func newTestScope(vars map[string]string) *variableScope {
	scope := newScope()
	for name, value := range vars {
		scope.declare(name, &binding{value: value, done: true})
	}
	scope.next++
	return scope
}

// snapshot returns every visible variable with its value.
func (s *variableScope) snapshot() map[string]string {
	out := map[string]string{}
	for _, name := range s.Keys() {
		out[name], _ = s.Get(name)
	}
	return out
}
