package docker

// newTestScope returns an immutable env tree whose variables are already
// resolved, as if declared with literal values.
func newTestScope(vars map[string]string) *envNode {
	var env *envNode
	for name, value := range vars {
		env = env.set(name, &binding{value: value, done: true})
	}
	return env
}

// snapshot resolves and returns every variable in env.
func snapshotEnv(env *envNode) map[string]string {
	out := map[string]string{}
	for _, name := range env.keys(nil) {
		b, _ := env.get(name)
		if !b.done {
			resolveBindings([]*binding{b})
		}
		out[name] = b.value
	}
	return out
}
