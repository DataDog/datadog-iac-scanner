/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 *
 * This product includes software developed at Datadog (https://www.datadoghq.com)  Copyright 2024 Datadog, Inc.
 */

// Package eval runs a Pulumi program against the scanner's fake engine and
// returns what it declares, one capture document per stack.
//
// Evaluating executes the repository's code. The program runs in its own
// process group with a timeout, with an environment built from scratch so that
// SDKs do not pick up credentials or configuration by accident, and is never
// given the means to install anything: its dependencies must be prepared
// beforehand. This is not isolation: the program has the scanner's user,
// filesystem and network access. Only evaluate in a disposable environment
// that holds no secret and has no network access the program should not have.
package eval

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DataDog/datadog-iac-scanner/pkg/logger"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/capture"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/engine"
	"github.com/DataDog/datadog-iac-scanner/pkg/pulumi/placeholders"
)

// Defaults of Options.
const (
	DefaultTimeout      = 120 * time.Second
	DefaultBuildTimeout = 10 * time.Minute
	DefaultMaxAttempts  = 20
)

const (
	filePerm = 0o600
	dirPerm  = 0o700
)

// Options configure an evaluation.
type Options struct {
	// Root is the scan root: capture paths are relative to it. Defaults to the project directory.
	Root string
	// Stacks restricts the evaluation to these stacks (default: every committed stack).
	Stacks []string
	// Timeout bounds the evaluation of one stack, configuration retries included.
	Timeout time.Duration
	// BuildTimeout bounds the build of a Go program.
	BuildTimeout time.Duration
	// MaxResources caps the resources recorded per stack.
	MaxResources int
	// MaxAttempts bounds the runs per stack (one more per missing configuration key).
	MaxAttempts int
	// Python is the interpreter to use (default: the project's virtualenv, then python3 on PATH).
	Python string
	// Go is the Go toolchain (default: go on PATH).
	Go string
	// GoModCache and GoCache are the prepared Go caches (default: the scanner's).
	GoModCache, GoCache string
}

func (o *Options) withDefaults(projectDir string) {
	if o.Root == "" {
		o.Root = projectDir
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.BuildTimeout <= 0 {
		o.BuildTimeout = DefaultBuildTimeout
	}
	if o.MaxResources <= 0 {
		o.MaxResources = engine.DefaultMaxResources
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = DefaultMaxAttempts
	}
	if o.GoModCache == "" || o.GoCache == "" {
		modCache, cache := defaultGoCaches()
		if o.GoModCache == "" {
			o.GoModCache = modCache
		}
		if o.GoCache == "" {
			o.GoCache = cache
		}
	}
}

// launcher builds the command that runs a program for one stack.
type launcher interface {
	command(p *Project, stack, addr string, env childEnv) *command
}

type evaluator struct {
	opts     Options
	project  *Project
	relDir   string
	env      childEnv
	launcher launcher
	src      *sourceIndex
}

// Evaluate runs the Pulumi project in projectDir once per stack.
//
// It returns an error only when the project cannot be read, or when ctx is
// canceled: the evaluation then stops, and the error wraps ctx.Err(). A
// program that cannot run, or fails, gives documents with a failed or skipped
// result.
func Evaluate(ctx context.Context, projectDir string, options *Options) ([]capture.Document, error) {
	e, stacks, err := newEvaluator(projectDir, options)
	if err != nil {
		return nil, err
	}
	switch {
	case e.project.Runtime != RuntimePython && e.project.Runtime != RuntimeGo:
		return e.all(stacks, capture.StatusSkipped, &failure{capture.ReasonUnsupportedRuntime,
			"pulumi project not evaluated: unsupported runtime " + e.project.Runtime}), nil
	case !osSupported:
		return e.all(stacks, capture.StatusSkipped, &failure{capture.ReasonOSUnsupported,
			"pulumi evaluation not supported on Windows"}), nil
	}

	workDir, err := os.MkdirTemp("", "dd-pulumi-eval-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	home, tmp := filepath.Join(workDir, "home"), filepath.Join(workDir, "tmp")
	for _, d := range []string{home, tmp} {
		if err := os.MkdirAll(d, dirPerm); err != nil {
			return nil, err
		}
	}
	e.env = newChildEnv(home, tmp)

	f := e.prepare(ctx, workDir)
	if err := interrupted(ctx); err != nil {
		return nil, err
	}
	if f != nil {
		return e.all(stacks, capture.StatusFailed, f), nil
	}
	e.src = newSourceIndex(e.project.Dir)
	docs := make([]capture.Document, 0, len(stacks))
	for i := range stacks {
		doc := e.evaluateStack(ctx, &stacks[i])
		if err := interrupted(ctx); err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

// interrupted returns an error wrapping ctx.Err() once ctx is canceled: what
// ran then was killed, so its result says nothing about the program.
func interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("pulumi evaluation interrupted: %w", err)
	}
	return nil
}

// newEvaluator reads the project and its stacks.
func newEvaluator(projectDir string, options *Options) (*evaluator, []Stack, error) {
	opts := Options{}
	if options != nil {
		opts = *options
	}
	p, err := LoadProject(projectDir)
	if err != nil {
		return nil, nil, err
	}
	stacks, err := p.Stacks()
	if err != nil {
		return nil, nil, err
	}
	if stacks, err = selectStacks(stacks, opts.Stacks); err != nil {
		return nil, nil, err
	}
	opts.withDefaults(p.Dir)
	if opts.Root, err = filepath.Abs(opts.Root); err != nil {
		return nil, nil, err
	}
	rel, err := filepath.Rel(opts.Root, p.Dir)
	if err != nil || !under(opts.Root, p.Dir) {
		return nil, nil, fmt.Errorf("project %s is not under the scan root %s", p.Dir, opts.Root)
	}
	return &evaluator{opts: opts, project: p, relDir: filepath.ToSlash(rel)}, stacks, nil
}

func (e *evaluator) prepare(ctx context.Context, workDir string) *failure {
	if e.project.Runtime == RuntimeGo {
		l, f := newGoLauncher(ctx, e.project, &e.opts, workDir, e.env)
		if f != nil {
			return f
		}
		e.launcher = l
		return nil
	}
	l, msg, err := newPythonLauncher(e.project, e.opts.Python, workDir, e.env)
	if err != nil {
		if msg == "" {
			msg = err.Error()
		}
		return &failure{capture.ReasonRuntimeMissing, msg}
	}
	e.launcher = l
	return nil
}

func selectStacks(stacks []Stack, wanted []string) ([]Stack, error) {
	if len(wanted) == 0 {
		return stacks, nil
	}
	byName := map[string]Stack{}
	for _, s := range stacks {
		byName[s.Name] = s
	}
	out := make([]Stack, 0, len(wanted))
	for _, name := range wanted {
		s, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("stack %q not found", name)
		}
		out = append(out, s)
	}
	return out, nil
}

func (e *evaluator) document(st *Stack) capture.Document {
	return capture.Document{
		FormatVersion:  capture.FormatVersion,
		Project:        e.project.Name,
		Stack:          st.Name,
		SyntheticStack: st.File == "",
		Runtime:        e.project.Runtime,
		ProjectDir:     e.relDir,
		Resources:      []capture.Resource{},
	}
}

func (e *evaluator) all(stacks []Stack, status capture.Status, f *failure) []capture.Document {
	docs := make([]capture.Document, 0, len(stacks))
	for i := range stacks {
		d := e.document(&stacks[i])
		d.Result = capture.Result{Status: status, Reason: f.reason, Message: f.message}
		docs = append(docs, d)
	}
	return docs
}

type attempt struct {
	snap   engine.Snapshot
	run    runResult
	output string
	err    error
}

func (a *attempt) ok() bool { return a.err == nil && a.run.err == nil && !a.snap.Capped }

func (e *evaluator) evaluateStack(ctx context.Context, st *Stack) capture.Document {
	log := logger.FromContext(ctx)
	doc := e.document(st)
	cfg := newStackConfig(e.project, st, e.src)
	start := time.Now()
	deadline := start.Add(e.opts.Timeout)

	var last attempt
	for n := 1; n <= e.opts.MaxAttempts; n++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			last.run.timedOut = true
			break
		}
		last = e.run(ctx, st.Name, cfg, remaining)
		doc.Result.Attempts = n
		log.Debug().Str("project", e.project.Dir).Str("stack", st.Name).Int("attempt", n).
			Int("resources", len(last.snap.Resources)).Bool("ok", last.ok()).Msg("pulumi evaluation attempt")
		if last.ok() || last.err != nil || last.run.timedOut || last.snap.Capped || ctx.Err() != nil {
			break
		}
		if !e.retryConfig(cfg, last.output) {
			break
		}
	}

	doc.Resources = append(doc.Resources, last.snap.Resources...)
	doc.Invokes, doc.Reads = last.snap.Invokes, last.snap.Reads
	doc.Config = capture.Config{
		Values:           cfg.publicValues(),
		Placeholders:     sortedKeys(cfg.placeholders),
		ProviderDefaults: sortedKeys(cfg.providerDefaults),
		Secrets:          sortedKeys(cfg.secrets),
	}
	doc.Result.DurationMillis = time.Since(start).Milliseconds()
	switch {
	case last.err != nil:
		doc.Result.Status, doc.Result.Reason, doc.Result.Message = capture.StatusFailed, capture.ReasonProgramError, last.err.Error()
	case last.snap.Capped:
		doc.Result.Status, doc.Result.Reason = capture.StatusFailed, capture.ReasonResourceCap
		doc.Result.Message = fmt.Sprintf("more than %d resources", e.opts.MaxResources)
	case last.run.timedOut:
		doc.Result.Status, doc.Result.Reason = capture.StatusFailed, capture.ReasonTimeout
		doc.Result.Message = "did not finish in " + e.opts.Timeout.String()
	case last.ok():
		doc.Result.Status = capture.StatusEvaluated
		doc.Result.Partial = len(doc.Config.Placeholders) > 0
	default:
		doc.Result.Status = capture.StatusFailed
		doc.Result.Reason, doc.Result.Detail = classifyProgram(last.output, len(last.snap.Invokes) > 0, last.snap.Unimplemented)
		doc.Result.Message = excerpt(last.output)
	}
	return doc
}

// run starts a fake engine and runs the program once against it.
func (e *evaluator) run(ctx context.Context, stack string, cfg *stackConfig, timeout time.Duration) attempt {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv, err := engine.Start(&engine.Options{
		Project:      e.project.Name,
		Stack:        stack,
		Root:         e.opts.Root,
		ProjectDir:   e.project.Dir,
		MaxResources: e.opts.MaxResources,
		Placeholder:  placeholders.Invoke,
		OnCapped:     cancel,
	})
	if err != nil {
		return attempt{err: err}
	}
	defer srv.Stop()

	cmd := e.launcher.command(e.project, stack, srv.Addr(), e.env.withPulumi(srv.Addr(), e.project, stack, cfg))
	cmd.timeout = timeout
	res := run(runCtx, cmd)
	snap := srv.Snapshot()

	var out strings.Builder
	out.WriteString(res.output)
	for _, l := range snap.Logs {
		if l.Severity == "error" || l.Severity == "warning" {
			out.WriteString("\n" + l.Message)
		}
	}
	return attempt{snap: snap, run: res, output: out.String()}
}

// retryConfig gives a placeholder to the configuration key the program
// reported as missing or invalid. It returns false when there is nothing to retry.
func (e *evaluator) retryConfig(cfg *stackConfig, output string) bool {
	if m := missingConfig.FindStringSubmatch(output); m != nil {
		if _, tried := cfg.tried[m[1]]; tried {
			return cfg.nextCandidate(m[1], e.src)
		}
		cfg.addPlaceholder(m[1], e.src)
		return true
	}
	if m := invalidConfig.FindStringSubmatch(output); m != nil {
		key := m[1]
		if key == "" {
			key = m[2]
		}
		return cfg.nextCandidate(qualify(key, e.project.Name), e.src)
	}
	if m := requiredByProgram.FindStringSubmatch(output); len(m) > 1 && cfg.values[m[1]] == "" {
		cfg.addPlaceholder(m[1], e.src)
		return true
	}
	return false
}
