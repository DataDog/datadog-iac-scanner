/*
 * Unless explicitly stated otherwise all files in this repository are licensed under the Apache-2.0 License.
 * This product includes software developed at Datadog (https://www.datadoghq.com) Copyright 2026 Datadog, Inc.
 */
package gitlab

import (
	"cmp"
	"context"
	"math"
	"strings"
	"unicode/utf8"
)

type globOp uint8

const (
	globLiteral globOp = iota
	globSplit
	globEmpty
	globAccept
)

type globInstruction struct {
	op       globOp
	out, alt int
	literal  rune
}
type globPatch struct{ instruction, next int }
type globFragment struct{ start, head, tail int }
type globGroup struct {
	prefix, alternatives globFragment
	hasAlternative       bool
}

// Braces describe a language of patterns. Retain that language as a graph,
// rather than expanding its Cartesian product. The matcher interprets glob
// tokens on this graph, after brace processing, as Ruby File.fnmatch does.
type gitlabGlob struct {
	ctx     context.Context
	code    []globInstruction
	patches []globPatch
	start   int
	prefix  string
}

func emptyGlobFragment() globFragment { return globFragment{-1, -1, -1} }

type globCompiler struct {
	program *gitlabGlob
	current globFragment
	groups  []globGroup
}

func (c *globCompiler) group(char rune) bool {
	switch {
	case char == '{':
		if Reserve(c.program.ctx, 0, nodeAllocationBytes) {
			c.groups = append(c.groups, globGroup{prefix: c.current, alternatives: emptyGlobFragment()})
			c.current = emptyGlobFragment()
		}
	case char == ',' && len(c.groups) > 0:
		group := &c.groups[len(c.groups)-1]
		if group.hasAlternative {
			group.alternatives = c.program.alternate(group.alternatives, c.current)
		} else {
			group.alternatives, group.hasAlternative = c.current, true
		}
		c.current = emptyGlobFragment()
	case char == '}' && len(c.groups) > 0:
		group := c.groups[len(c.groups)-1]
		c.groups = c.groups[:len(c.groups)-1]
		if group.hasAlternative {
			c.current = c.program.alternate(group.alternatives, c.current)
		}
		c.current = c.program.concatenate(group.prefix, c.current)
	default:
		return false
	}
	return true
}

func compileGitLabGlob(ctx context.Context, pattern string) *gitlabGlob {
	p := &gitlabGlob{ctx: ctx, start: -1}
	c := globCompiler{program: p, current: emptyGlobFragment()}
	var prefix strings.Builder
	meta := false
	for index := 0; index < len(pattern) && ctx.Err() == nil; {
		char, size := utf8.DecodeRuneInString(pattern[index:])
		index += size
		if char == '\\' {
			if index == len(pattern) {
				return p
			}
			escaped, count := utf8.DecodeRuneInString(pattern[index:])
			index += count
			c.current = p.concatenate(c.current, p.emit(char))
			c.current = p.concatenate(c.current, p.emit(escaped))
			if !meta {
				prefix.WriteRune(escaped)
			}
			continue
		}
		if char == '{' {
			meta = true
		}
		if c.group(char) {
			continue
		}
		if strings.ContainsRune("*?[", char) {
			meta = true
		}
		if !meta {
			prefix.WriteRune(char)
		}
		c.current = p.concatenate(c.current, p.emit(char))
	}
	if len(c.groups) != 0 || ctx.Err() != nil {
		return p
	}
	accept := p.emitInstruction(globInstruction{op: globAccept})
	current := p.concatenate(c.current, accept)
	p.start = current.start
	if slash := strings.LastIndexByte(prefix.String(), '/'); slash >= 0 {
		p.prefix = prefix.String()[:slash]
	}
	p.patches = nil
	return p
}

func (p *gitlabGlob) emit(char rune) globFragment {
	return p.emitInstruction(globInstruction{op: globLiteral, literal: char})
}

func (p *gitlabGlob) emitInstruction(instruction globInstruction) globFragment {
	if !Reserve(p.ctx, 1, nodeAllocationBytes) {
		return emptyGlobFragment()
	}
	index, patch := len(p.code), len(p.patches)
	instruction.out, instruction.alt = -1, -1
	p.code = append(p.code, instruction)
	p.patches = append(p.patches, globPatch{index, -1})
	return globFragment{index, patch, patch}
}

func (p *gitlabGlob) concatenate(left, right globFragment) globFragment {
	if left.start < 0 {
		return right
	}
	if right.start < 0 {
		return left
	}
	for patch := left.head; patch >= 0; patch = p.patches[patch].next {
		p.code[p.patches[patch].instruction].out = right.start
	}
	return globFragment{left.start, right.head, right.tail}
}

func (p *gitlabGlob) alternate(left, right globFragment) globFragment {
	if left.start < 0 {
		left = p.emitInstruction(globInstruction{op: globEmpty})
	}
	if right.start < 0 {
		right = p.emitInstruction(globInstruction{op: globEmpty})
	}
	if left.start < 0 || right.start < 0 || !Reserve(p.ctx, 1, nodeAllocationBytes) {
		return emptyGlobFragment()
	}
	start := len(p.code)
	p.code = append(p.code, globInstruction{op: globSplit, out: left.start, alt: right.start})
	p.patches[left.tail].next = right.head
	return globFragment{start, left.head, right.tail}
}

const (
	globWithinComponent = iota
	globComponentStart
	globEscape
	globAny
	globClass
	globFirstStar
	globSecondStar
	globThirdStar
	globFirstStarAtStart
	globSecondStarAtStart
	globThirdStarAtStart
	globStarLoop
	globDirectoryInside
	globDirectoryBoundary
	globClassMode
)

const (
	classInitial = iota
	classLow
	classAfterLow
	classDash
	classEscapedLow
	classEscapedHigh
	classPhases
)

const (
	classRelations  = 3
	classFlags      = 4
	globModes       = globClassMode + classPhases*classFlags*classRelations
	starCounts      = 3
	classStateBytes = nodeAllocationBytes / 2
)

type globMachine struct {
	program                       *gitlabGlob
	seen                          map[int]uint64
	generation                    uint64
	left, right, pending, classes []int
}

func (p *gitlabGlob) machine() *globMachine {
	if p.start < 0 || len(p.code) > math.MaxInt/globModes {
		return nil
	}
	return &globMachine{program: p, seen: make(map[int]uint64)}
}

func (m *globMachine) nextGeneration() {
	m.generation++
	if m.generation == 0 {
		clear(m.seen)
		m.generation = 1
	}
}

func (m *globMachine) mark(state int) bool {
	previous, exists := m.seen[state]
	if previous == m.generation {
		return false
	}
	if !exists && !Reserve(m.program.ctx, 1, classStateBytes) {
		return false
	}
	m.seen[state] = m.generation
	return true
}

func (m *globMachine) enqueue(index, mode int) { m.pending = append(m.pending, index*globModes+mode) }

func (m *globMachine) closure(states, output []int) []int {
	m.pending = append(m.pending[:0], states...)
	output = output[:0]
	for len(m.pending) > 0 && m.program.ctx.Err() == nil {
		state := m.pending[len(m.pending)-1]
		m.pending = m.pending[:len(m.pending)-1]
		if !m.mark(state) {
			continue
		}
		index, mode := state/globModes, state%globModes
		instruction := &m.program.code[index]
		if mode >= globFirstStar && mode <= globThirdStarAtStart {
			m.starClosure(index, mode)
			continue
		}
		if mode >= globAny && mode <= globClass {
			output = append(output, state)
			continue
		}
		switch mode {
		case globStarLoop:
			m.enqueue(index, globWithinComponent)
			output = append(output, state)
		case globDirectoryBoundary:
			m.enqueue(instruction.out, globComponentStart)
			output = append(output, state)
		case globDirectoryInside:
			output = append(output, state)
		default:
			output = m.normalClosure(index, mode, state, output)
		}
	}
	return output
}

func (m *globMachine) branches(index, mode int) bool {
	instruction := &m.program.code[index]
	if instruction.op == globSplit {
		m.enqueue(instruction.out, mode)
		m.enqueue(instruction.alt, mode)
		return true
	}
	if instruction.op == globEmpty {
		m.enqueue(instruction.out, mode)
		return true
	}
	return false
}

func (m *globMachine) normalClosure(index, mode, state int, output []int) []int {
	if m.branches(index, mode) {
		return output
	}
	instruction := &m.program.code[index]
	if mode == globEscape {
		if instruction.op == globLiteral {
			return append(output, state)
		}
		return output
	}
	if instruction.op == globAccept {
		return append(output, state)
	}
	switch instruction.literal {
	case '*':
		star := globFirstStar
		if mode == globComponentStart {
			star = globFirstStarAtStart
		}
		m.enqueue(instruction.out, star)
	case '?':
		m.enqueue(instruction.out, globAny)
	case '[':
		m.enqueue(instruction.out, globClass)
	case '\\':
		m.enqueue(instruction.out, globEscape)
	default:
		output = append(output, state)
	}
	return output
}

func (m *globMachine) starClosure(index, mode int) {
	if m.branches(index, mode) {
		return
	}
	instruction := &m.program.code[index]
	count := (mode-globFirstStar)%starCounts + 1
	atStart := mode >= globFirstStarAtStart
	if instruction.op == globLiteral && instruction.literal == '*' {
		if count < starCounts {
			mode++
		}
		m.enqueue(instruction.out, mode)
		return
	}
	m.enqueue(index, globWithinComponent)
	m.enqueue(index, globStarLoop)
	if count == 2 && atStart && instruction.op == globLiteral && instruction.literal == '/' {
		m.enqueue(index, globDirectoryBoundary)
	}
}

func (m *globMachine) start() []int {
	m.nextGeneration()
	m.left = m.closure([]int{m.program.start*globModes + globComponentStart}, m.left)
	return m.left
}

func (m *globMachine) advance(states []int, text string) []int {
	m.left = append(m.left[:0], states...)
	for _, char := range text {
		m.nextGeneration()
		m.right = m.right[:0]
		for _, state := range m.left {
			m.consume(state, char)
		}
		m.left = m.closure(m.right, m.left)
		if len(m.left) == 0 {
			break
		}
	}
	return m.left
}

func (m *globMachine) consume(state int, char rune) {
	index, mode := state/globModes, state%globModes
	instruction := &m.program.code[index]
	switch mode {
	case globAny:
		if char != '/' {
			m.right = append(m.right, index*globModes+globWithinComponent)
		}
	case globClass:
		if char != '/' {
			m.scanClass(index, char)
		}
	case globStarLoop:
		if char != '/' {
			m.right = append(m.right, state)
		}
	case globDirectoryInside, globDirectoryBoundary:
		next := globDirectoryInside
		if char == '/' {
			if mode == globDirectoryBoundary {
				return
			}
			next = globDirectoryBoundary
		}
		m.right = append(m.right, index*globModes+next)
	default:
		if instruction.op == globLiteral && instruction.literal == char {
			next := globWithinComponent
			if char == '/' {
				next = globComponentStart
			}
			m.right = append(m.right, instruction.out*globModes+next)
		}
	}
}

type globClassContext struct {
	phase, low    int
	negate, found bool
}

func (state globClassContext) mode() int {
	flags := 0
	if state.negate {
		flags += 2
	}
	if state.found {
		flags++
	}
	return globClassMode + (state.phase*classFlags+flags)*classRelations + state.low + 1
}

func decodeGlobClass(mode int) globClassContext {
	value := mode - globClassMode
	state := globClassContext{low: value%classRelations - 1}
	value /= classRelations
	state.phase = value / classFlags
	flags := value % classFlags
	state.negate, state.found = flags&2 != 0, flags&1 != 0
	return state
}

func (m *globMachine) scanClass(index int, char rune) {
	m.classes = append(m.classes[:0], index*globModes+(globClassContext{phase: classInitial}).mode())
	for len(m.classes) > 0 && m.program.ctx.Err() == nil {
		state := m.classes[len(m.classes)-1]
		m.classes = m.classes[:len(m.classes)-1]
		if !m.mark(state) {
			continue
		}
		index, mode := state/globModes, state%globModes
		instruction := &m.program.code[index]
		switch instruction.op {
		case globSplit:
			m.classes = append(m.classes, instruction.out*globModes+mode, instruction.alt*globModes+mode)
		case globEmpty:
			m.classes = append(m.classes, instruction.out*globModes+mode)
		case globLiteral:
			state := decodeGlobClass(mode)
			closed := state.read(instruction.literal, char)
			if closed {
				if state.found != state.negate {
					m.right = append(m.right, instruction.out*globModes+globWithinComponent)
				}
			} else {
				m.classes = append(m.classes, instruction.out*globModes+state.mode())
			}
		}
	}
}

func (state *globClassContext) read(pattern, char rune) bool {
	switch state.phase {
	case classInitial:
		state.phase = classLow
		if pattern == '!' || pattern == '^' {
			state.negate = true
			return false
		}
		return state.readLow(pattern, char)
	case classLow:
		return state.readLow(pattern, char)
	case classAfterLow:
		if pattern == '-' {
			state.phase = classDash
			return false
		}
		state.found = state.found || state.low == 0
		return state.readLow(pattern, char)
	case classDash:
		if pattern == ']' {
			state.found = state.found || state.low == 0 || char == '-'
			return true
		}
		if pattern == '\\' {
			state.phase = classEscapedHigh
			return false
		}
		state.readHigh(pattern, char)
	case classEscapedHigh:
		state.readHigh(pattern, char)
	case classEscapedLow:
		state.low, state.phase = cmp.Compare(pattern, char), classAfterLow
	}
	return false
}

func (state *globClassContext) readLow(pattern, char rune) bool {
	if pattern == ']' {
		return true
	}
	if pattern == '\\' {
		state.phase = classEscapedLow
		return false
	}
	state.low, state.phase = cmp.Compare(pattern, char), classAfterLow
	return false
}

func (state *globClassContext) readHigh(pattern, char rune) {
	high := cmp.Compare(pattern, char)
	state.found = state.found || state.low == 0 || high == 0 || (state.low < 0 && high > 0)
	state.low, state.phase = 0, classLow
}

func (m *globMachine) accepts(states []int) bool {
	for _, state := range states {
		if state%globModes <= globComponentStart && m.program.code[state/globModes].op == globAccept {
			return true
		}
	}
	return false
}
