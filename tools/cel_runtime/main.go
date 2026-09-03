// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

// skill-scanner-cel-go is a bounded, persistent CEL evaluation helper.
//
// The Python scanner sends one atomically compiled rule generation followed by
// many protobuf activations. The helper never reads source packages, imports
// extensions, opens sockets, or executes user-controlled programs.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp/syntax"
	"runtime/debug"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	celenv "cel.dev/cel-go/common/env"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/interpreter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	protocolVersion          = 2
	runtimeName              = "cel-go"
	celGoVersion             = "v0.32.0"
	scanFactsType            = "skill_scanner.semantic.v1.ScanFacts"
	canonicalDescriptorHash  = "0dd0799a2276e2f6fc844bc1da5835e2a05ccbca3802d1dea635d3b0d4cd1a13"
	supportedFactSchema      = "v1"
	maxFrameBytes            = 16 * 1024 * 1024
	maxJSONNestingDepth      = 64
	maxDescriptorBytes       = 1024 * 1024
	maxDescriptorFiles       = 16
	maxFactsBytes            = 2 * 1024 * 1024
	maxBatchItems            = 4096
	maxBatchFactsBytes       = 8 * 1024 * 1024
	maxStringBytes           = 4 * 1024
	maxFiles                 = 1024
	maxRepeatedItems         = 4096
	maxSemanticItems         = 4096
	maxRules                 = 1024
	maxRuleIDBytes           = 256
	maxExpressionBytes       = 16 * 1024
	maxTotalExpressionBytes  = 4 * 1024 * 1024
	maxExpressionNodes       = 4096
	maxTotalExpressionNodes  = maxExpressionNodes * 16
	maxExpressionDepth       = 64
	maxComprehensionDepth    = 2
	maxLiteralRegexChars     = 512
	maxFactAccessPaths       = 4096
	maxFactAccessPathBytes   = 4096
	maxTotalFactAccessBytes  = 4 * 1024 * 1024
	maxProtoRecursionDepth   = 64
	parserRecursionLimit     = 64
	parserErrorRecoveryLimit = 8
	maxRegexProgramSize      = 4096
	defaultEvalTimeoutMillis = 50
	maxEvalTimeoutMillis     = 50
	defaultCostLimit         = 1_000_000
	maxCostLimit             = 1_000_000
	interruptCheckFrequency  = 32
)

// helperVersion is overridden by release builds with:
// -ldflags "-X main.helperVersion=<release-version>".
var helperVersion = "development"

type wireRule struct {
	RuleID     string `json:"rule_id"`
	Expression string `json:"expression"`
	FactSchema string `json:"fact_schema"`
}

type wireBatchItem struct {
	RuleID   string `json:"rule_id"`
	FactsB64 string `json:"facts_b64"`
}

type wireBatchResult struct {
	OK         bool    `json:"ok"`
	Value      *bool   `json:"value,omitempty"`
	ElapsedMS  float64 `json:"elapsed_ms"`
	ActualCost uint64  `json:"actual_cost"`
	ErrorCode  string  `json:"error_code,omitempty"`
}

type wireRequest struct {
	ProtocolVersion   int             `json:"protocol_version"`
	Type              string          `json:"type"`
	RequestID         uint64          `json:"request_id"`
	ExpressionSetHash string          `json:"expression_set_hash,omitempty"`
	DescriptorB64     string          `json:"descriptor_b64,omitempty"`
	Rules             []wireRule      `json:"rules,omitempty"`
	RuleID            string          `json:"rule_id,omitempty"`
	FactsB64          string          `json:"facts_b64,omitempty"`
	Items             []wireBatchItem `json:"items,omitempty"`
	EvalTimeoutMS     uint64          `json:"eval_timeout_ms,omitempty"`
	CostLimit         uint64          `json:"cost_limit,omitempty"`
}

type wireResponse struct {
	ProtocolVersion   int                  `json:"protocol_version"`
	Type              string               `json:"type"`
	RequestID         uint64               `json:"request_id"`
	OK                bool                 `json:"ok"`
	Value             *bool                `json:"value,omitempty"`
	ElapsedMS         float64              `json:"elapsed_ms,omitempty"`
	ActualCost        uint64               `json:"actual_cost,omitempty"`
	ErrorCode         string               `json:"error_code,omitempty"`
	Message           string               `json:"message,omitempty"`
	Runtime           string               `json:"runtime,omitempty"`
	RuntimeVersion    string               `json:"runtime_version,omitempty"`
	HelperVersion     string               `json:"helper_version,omitempty"`
	ExpressionSetHash string               `json:"expression_set_hash,omitempty"`
	DescriptorHash    string               `json:"descriptor_hash,omitempty"`
	RuleCount         int                  `json:"rule_count,omitempty"`
	FactAccessPaths   *map[string][]string `json:"fact_access_paths,omitempty"`
	Results           *[]wireBatchResult   `json:"results,omitempty"`
}

type compiledGeneration struct {
	programs          map[string]cel.Program
	messageDescriptor protoreflect.MessageDescriptor
	expressionSetHash string
	descriptorHash    string
	evalTimeout       time.Duration
	factAccessPaths   map[string][]string
}

type runtimeServer struct {
	generation *compiledGeneration
}

var subsetReservedIdentifiers = map[string]struct{}{
	"as": {}, "break": {}, "const": {}, "continue": {}, "else": {}, "false": {},
	"for": {}, "function": {}, "has": {}, "if": {}, "import": {}, "in": {},
	"let": {}, "loop": {}, "namespace": {}, "null": {}, "package": {}, "return": {},
	"true": {}, "var": {}, "void": {}, "while": {},
}

// newSkillScannerCELEnv builds the CEL environment from an explicit standard
// library allowlist. The AST validator below is still authoritative for source
// shape (for example literal-only string arguments), but unsupported operators
// and functions are unavailable to the checker and evaluator as defense in
// depth.
func newSkillScannerCELEnv(descriptorSet *descriptorpb.FileDescriptorSet) (*cel.Env, error) {
	subset := celenv.NewLibrarySubset().
		AddIncludedMacros(operators.Has, operators.Exists, operators.All).
		AddIncludedFunctions(
			&celenv.Function{Name: operators.LogicalAnd},
			&celenv.Function{Name: operators.LogicalOr},
			&celenv.Function{Name: operators.LogicalNot},
			&celenv.Function{Name: operators.NotStrictlyFalse},
			&celenv.Function{Name: operators.Equals},
			&celenv.Function{Name: operators.NotEquals},
			&celenv.Function{Name: operators.Less},
			&celenv.Function{Name: operators.LessEquals},
			&celenv.Function{Name: operators.Greater},
			&celenv.Function{Name: operators.GreaterEquals},
			&celenv.Function{Name: operators.In},
			&celenv.Function{Name: overloads.StartsWith},
			&celenv.Function{Name: overloads.EndsWith},
			&celenv.Function{Name: overloads.Contains},
			&celenv.Function{Name: overloads.Matches},
		)
	return cel.NewCustomEnv(
		cel.StdLib(cel.StdLibSubset(subset)),
		cel.TypeDescs(descriptorSet),
		cel.Variable("f", cel.ObjectType(scanFactsType)),
		cel.EnableMacroCallTracking(),
		cel.EnableErrorOnBadPresenceTest(true),
		cel.EagerlyValidateDeclarations(true),
		cel.ParserExpressionSizeLimit(maxExpressionBytes),
		cel.ParserRecursionLimit(parserRecursionLimit),
		cel.ParserErrorRecoveryLimit(parserErrorRecoveryLimit),
		cel.ExpressionNodeLimit(maxExpressionNodes),
		cel.ExpressionNestingDepthLimit(maxExpressionDepth),
	)
}

type subsetValidator struct {
	checked        *celast.AST
	macroCalls     map[int64]celast.Expr
	rootDescriptor protoreflect.MessageDescriptor
	nodes          int
	foundRoot      bool
	bindings       map[string]int
}

// validateExpressionSubset independently verifies the checked AST. This is
// intentionally narrower than CEL: expressions may correlate typed ScanFacts,
// but may not construct data, index values, do arithmetic, call extensions, or
// synthesize dynamic regular expressions.
func validateExpressionSubset(
	checked *cel.Ast,
	rootDescriptor protoreflect.MessageDescriptor,
) (nodeCount int, err error) {
	defer func() {
		if recover() != nil {
			nodeCount = 0
			err = errors.New("CEL subset validation panicked while rejecting an expression")
		}
	}()
	if checked == nil || checked.NativeRep() == nil || !checked.IsChecked() || rootDescriptor == nil {
		return 0, errors.New("CEL expression is not a checked AST")
	}
	native := checked.NativeRep()
	// ExceedsDepth is bounded and therefore safe before any recursive AST walk.
	// Its threshold is exclusive for our limit: depth 64 is permitted.
	if celast.ExceedsDepth(native, maxExpressionDepth+1) {
		return 0, fmt.Errorf("CEL expression AST depth exceeds %d", maxExpressionDepth)
	}
	nodeCount = celast.NodeCount(native)
	if nodeCount > maxExpressionNodes {
		return 0, fmt.Errorf("CEL expression exceeds %d AST nodes", maxExpressionNodes)
	}
	validator := &subsetValidator{
		checked:        native,
		macroCalls:     native.SourceInfo().MacroCalls(),
		rootDescriptor: rootDescriptor,
		bindings:       make(map[string]int),
	}
	if err := validator.validate(native.Expr(), 1, 0); err != nil {
		return nodeCount, err
	}
	if !validator.foundRoot {
		return nodeCount, errors.New("CEL expression must reference the typed root variable f")
	}
	return nodeCount, nil
}

func (validator *subsetValidator) addNode(depth int) error {
	validator.nodes++
	if validator.nodes > maxExpressionNodes {
		return fmt.Errorf("CEL expression exceeds %d AST nodes", maxExpressionNodes)
	}
	if depth > maxExpressionDepth {
		return fmt.Errorf("CEL expression AST depth exceeds %d", maxExpressionDepth)
	}
	return nil
}

func (validator *subsetValidator) validate(expression celast.Expr, depth int, comprehensionDepth int) error {
	if expression == nil || expression.Kind() == celast.UnspecifiedExprKind {
		return errors.New("CEL expression contains an unspecified AST node")
	}
	if err := validator.addNode(depth); err != nil {
		return err
	}
	// Macro-call IDs can overlap IDs inside the stored source-form macro calls.
	// Consult the expansion map only for AST shapes produced by our three
	// allowed macros, never for ordinary source nodes with a colliding ID.
	if expression.Kind() == celast.ComprehensionKind ||
		(expression.Kind() == celast.SelectKind && expression.AsSelect().IsTestOnly()) {
		if macroCall, ok := validator.macroCalls[expression.ID()]; ok {
			return validator.validateMacro(expression, macroCall, depth, comprehensionDepth)
		}
	}

	switch expression.Kind() {
	case celast.IdentKind:
		name := expression.AsIdent()
		if name == "f" {
			rootType := validator.checked.GetType(expression.ID())
			if rootType.Kind() != types.StructKind || rootType.TypeName() != scanFactsType {
				return errors.New("CEL root variable f does not have the canonical ScanFacts type")
			}
			validator.foundRoot = true
			return nil
		}
		if validator.bindings[name] > 0 {
			if !allowedSubsetType(validator.checked.GetType(expression.ID())) {
				return fmt.Errorf("CEL binding %q has a dynamic or unsupported type", name)
			}
			return nil
		}
		return fmt.Errorf("undeclared CEL identifier %q", name)
	case celast.LiteralKind:
		return validator.validateLiteral(expression)
	case celast.SelectKind:
		selection := expression.AsSelect()
		if selection.IsTestOnly() {
			return errors.New("protobuf presence tests are permitted only through has()")
		}
		if selection.FieldName() == "" {
			return errors.New("CEL field selection is missing a field name")
		}
		if !allowedSubsetType(validator.checked.GetType(expression.ID())) {
			return fmt.Errorf("CEL field %q has a dynamic or unsupported type", selection.FieldName())
		}
		if err := validator.validate(selection.Operand(), depth+1, comprehensionDepth); err != nil {
			return fmt.Errorf("CEL field %q operand: %w", selection.FieldName(), err)
		}
		return nil
	case celast.CallKind:
		return validator.validateCall(expression, depth, comprehensionDepth)
	case celast.ComprehensionKind:
		return errors.New("CEL comprehensions are permitted only through exists() or all()")
	case celast.ListKind, celast.MapKind, celast.StructKind:
		return errors.New("CEL list, map, and message construction is not permitted")
	default:
		return fmt.Errorf("CEL AST node kind %d is not permitted", expression.Kind())
	}
}

func allowedSubsetType(valueType *types.Type) bool {
	if valueType == nil {
		return false
	}
	switch valueType.Kind() {
	case types.BoolKind, types.StringKind, types.IntKind, types.UintKind, types.DoubleKind, types.StructKind:
		return true
	case types.ListKind:
		return len(valueType.Parameters()) == 1 && allowedSubsetType(valueType.Parameters()[0])
	default:
		return false
	}
}

func validateLiteralRegex(pattern string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("literal CEL regex validation panicked")
		}
	}()
	if utf8.RuneCountInString(pattern) > maxLiteralRegexChars {
		return fmt.Errorf("literal CEL regex exceeds %d characters", maxLiteralRegexChars)
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("invalid literal CEL regex: %w", err)
	}
	// regexp/syntax.Simplify expands bounded repetitions. Bound the expanded
	// instruction cost first so nested repeats cannot allocate an oversized
	// program merely while we validate the configured limit.
	if regexInstructionUpperBound(parsed, maxRegexProgramSize) > maxRegexProgramSize {
		return fmt.Errorf("literal CEL regex exceeds %d program instructions", maxRegexProgramSize)
	}
	program, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return fmt.Errorf("invalid literal CEL regex program: %w", err)
	}
	if len(program.Inst) > maxRegexProgramSize {
		return fmt.Errorf("literal CEL regex exceeds %d program instructions", maxRegexProgramSize)
	}
	return nil
}

func regexInstructionUpperBound(expression *syntax.Regexp, limit int) int {
	return saturatedAdd(regexInstructionCost(expression, limit), 2, limit)
}

func regexInstructionCost(expression *syntax.Regexp, limit int) int {
	if expression == nil {
		return limit + 1
	}
	var cost int
	switch expression.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpCharClass, syntax.OpAnyCharNotNL,
		syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		cost = 1
	case syntax.OpLiteral:
		cost = len(expression.Rune)
	case syntax.OpCapture:
		cost = saturatedAdd(regexInstructionCost(expression.Sub[0], limit), 2, limit)
	case syntax.OpConcat:
		for _, subexpression := range expression.Sub {
			cost = saturatedAdd(cost, regexInstructionCost(subexpression, limit), limit)
		}
	case syntax.OpAlternate:
		for _, subexpression := range expression.Sub {
			cost = saturatedAdd(cost, regexInstructionCost(subexpression, limit), limit)
		}
		if len(expression.Sub) > 1 {
			cost = saturatedAdd(cost, len(expression.Sub)-1, limit)
		}
	case syntax.OpQuest, syntax.OpStar, syntax.OpPlus:
		cost = saturatedAdd(regexInstructionCost(expression.Sub[0], limit), 1, limit)
	case syntax.OpRepeat:
		subCost := regexInstructionCost(expression.Sub[0], limit)
		cost = saturatedMultiply(subCost, expression.Min, limit)
		optionalCopies := expression.Max - expression.Min
		if expression.Max < 0 {
			optionalCopies = 1
		}
		if optionalCopies > 0 {
			optionalCost := saturatedAdd(subCost, 1, limit)
			cost = saturatedAdd(cost, saturatedMultiply(optionalCost, optionalCopies, limit), limit)
		}
	default:
		return limit + 1
	}
	return cost
}

func saturatedAdd(left int, right int, limit int) int {
	if left > limit || right > limit || left > limit-right {
		return limit + 1
	}
	return left + right
}

func saturatedMultiply(left int, right int, limit int) int {
	if left < 0 || right < 0 || left > limit || right > limit || (right != 0 && left > limit/right) {
		return limit + 1
	}
	return left * right
}

func (validator *subsetValidator) validateLiteral(expression celast.Expr) error {
	switch validator.checked.GetType(expression.ID()).Kind() {
	case types.BoolKind, types.StringKind, types.IntKind, types.UintKind, types.DoubleKind:
		return nil
	default:
		return fmt.Errorf(
			"CEL literal type %s is not permitted",
			validator.checked.GetType(expression.ID()).TypeName(),
		)
	}
}

func (validator *subsetValidator) validateCall(
	expression celast.Expr,
	depth int,
	comprehensionDepth int,
) error {
	call := expression.AsCall()
	function := call.FunctionName()
	args := call.Args()
	globalArities := map[string]int{
		operators.LogicalAnd:    2,
		operators.LogicalOr:     2,
		operators.LogicalNot:    1,
		operators.Equals:        2,
		operators.NotEquals:     2,
		operators.Less:          2,
		operators.LessEquals:    2,
		operators.Greater:       2,
		operators.GreaterEquals: 2,
		operators.In:            2,
	}
	if arity, ok := globalArities[function]; ok {
		if call.IsMemberFunction() || len(args) != arity {
			return fmt.Errorf("invalid CEL call shape for %q", function)
		}
		for _, argument := range args {
			if err := validator.validate(argument, depth+1, comprehensionDepth); err != nil {
				return fmt.Errorf("CEL call %q argument: %w", function, err)
			}
		}
		switch function {
		case operators.Equals, operators.NotEquals:
			if !validator.sameType(args[0], args[1]) {
				return fmt.Errorf("comparison %q requires identical operand types", function)
			}
		case operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
			if !validator.sameType(args[0], args[1]) {
				return fmt.Errorf("ordering comparison %q requires identical operand types", function)
			}
			switch validator.checked.GetType(args[0].ID()).Kind() {
			case types.IntKind, types.UintKind, types.DoubleKind, types.StringKind:
			default:
				return fmt.Errorf("ordering comparison %q has an unsupported operand type", function)
			}
		case operators.In:
			rightType := validator.checked.GetType(args[1].ID())
			if rightType.Kind() != types.ListKind || len(rightType.Parameters()) != 1 {
				return errors.New("operator in requires a repeated protobuf field on the right")
			}
			if !validator.checked.GetType(args[0].ID()).IsEquivalentType(rightType.Parameters()[0]) {
				return errors.New("operator in has incompatible element types")
			}
		}
		return nil
	}

	switch function {
	case overloads.StartsWith, overloads.EndsWith, overloads.Contains, overloads.Matches:
		if !call.IsMemberFunction() || len(args) != 1 {
			return fmt.Errorf("invalid CEL string method shape for %q", function)
		}
		if validator.checked.GetType(call.Target().ID()).Kind() != types.StringKind {
			return fmt.Errorf("CEL method %q requires a string receiver", function)
		}
		if err := validator.validate(call.Target(), depth+1, comprehensionDepth); err != nil {
			return fmt.Errorf("CEL method %q receiver: %w", function, err)
		}
		argument := args[0]
		if argument.Kind() != celast.LiteralKind ||
			validator.checked.GetType(argument.ID()).Kind() != types.StringKind {
			return fmt.Errorf("CEL method %q requires one literal string argument", function)
		}
		if err := validator.validate(argument, depth+1, comprehensionDepth); err != nil {
			return fmt.Errorf("CEL method %q argument: %w", function, err)
		}
		if function == overloads.Matches {
			literal, ok := argument.AsLiteral().(types.String)
			if !ok {
				return errors.New("CEL matches() argument is not a string literal")
			}
			if err := validateLiteralRegex(string(literal)); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("CEL function or operator %q is not permitted", function)
	}
}

func (validator *subsetValidator) validateMacro(
	expanded celast.Expr,
	macroExpression celast.Expr,
	depth int,
	comprehensionDepth int,
) error {
	if macroExpression.Kind() != celast.CallKind {
		return errors.New("invalid CEL macro source shape")
	}
	call := macroExpression.AsCall()
	args := call.Args()
	switch call.FunctionName() {
	case operators.Has:
		if call.IsMemberFunction() || len(args) != 1 || args[0].Kind() != celast.SelectKind ||
			args[0].AsSelect().IsTestOnly() {
			return errors.New("has() requires one protobuf field selection")
		}
		if expanded.Kind() != celast.SelectKind || !expanded.AsSelect().IsTestOnly() {
			return errors.New("has() did not expand to a protobuf presence test")
		}
		selection := expanded.AsSelect()
		if selection.FieldName() == "" || selection.FieldName() != args[0].AsSelect().FieldName() {
			return errors.New("has() expanded field does not match its source call")
		}
		if !validator.fieldHasExplicitPresence(selection.Operand(), selection.FieldName()) {
			return errors.New("has() requires a protobuf message field with explicit presence")
		}
		if err := validator.validate(selection.Operand(), depth+1, comprehensionDepth); err != nil {
			return fmt.Errorf("has() field: %w", err)
		}
		return nil
	case operators.Exists, operators.All:
		if !call.IsMemberFunction() || len(args) != 2 || args[0].Kind() != celast.IdentKind {
			return fmt.Errorf("%s() requires one binding and one predicate", call.FunctionName())
		}
		if expanded.Kind() != celast.ComprehensionKind {
			return fmt.Errorf("%s() did not expand to a comprehension", call.FunctionName())
		}
		binding := args[0].AsIdent()
		if binding == "f" {
			return errors.New("CEL comprehension binding cannot shadow the typed root variable f")
		}
		if _, reserved := subsetReservedIdentifiers[binding]; reserved {
			return fmt.Errorf("CEL comprehension binding %q is reserved", binding)
		}
		comprehensionDepth++
		if comprehensionDepth > maxComprehensionDepth {
			return fmt.Errorf("CEL comprehension nesting exceeds %d", maxComprehensionDepth)
		}
		comprehension := expanded.AsComprehension()
		if comprehension.HasIterVar2() || comprehension.IterVar() != binding {
			return fmt.Errorf("%s() expansion has an invalid iterator", call.FunctionName())
		}
		if err := validator.validate(comprehension.IterRange(), depth+1, comprehensionDepth); err != nil {
			return fmt.Errorf("%s() receiver: %w", call.FunctionName(), err)
		}
		targetType := validator.checked.GetType(comprehension.IterRange().ID())
		if targetType.Kind() != types.ListKind || len(targetType.Parameters()) != 1 {
			return fmt.Errorf("%s() requires a repeated protobuf field", call.FunctionName())
		}
		predicate, err := quantifierPredicate(comprehension, call.FunctionName())
		if err != nil {
			return err
		}
		if err := validator.addNode(depth + 1); err != nil {
			return err
		}
		validator.bindings[binding]++
		err = validator.validate(predicate, depth+1, comprehensionDepth)
		validator.bindings[binding]--
		if validator.bindings[binding] == 0 {
			delete(validator.bindings, binding)
		}
		if err != nil {
			return fmt.Errorf("%s() predicate: %w", call.FunctionName(), err)
		}
		if validator.checked.GetType(predicate.ID()).Kind() != types.BoolKind {
			return fmt.Errorf("%s() predicate must return bool", call.FunctionName())
		}
		return nil
	default:
		return fmt.Errorf("CEL macro %q is not permitted", call.FunctionName())
	}
}

func (validator *subsetValidator) fieldHasExplicitPresence(operand celast.Expr, fieldName string) bool {
	operandType := validator.checked.GetType(operand.ID())
	if operandType.Kind() != types.StructKind {
		return false
	}
	message := findMessageDescriptor(validator.rootDescriptor.ParentFile(), operandType.TypeName())
	if message == nil {
		return false
	}
	field := message.Fields().ByName(protoreflect.Name(fieldName))
	return field != nil && !field.IsList() && !field.IsMap() && field.HasPresence()
}

func findMessageDescriptor(
	file protoreflect.FileDescriptor,
	fullName string,
) protoreflect.MessageDescriptor {
	var findInMessages func(protoreflect.MessageDescriptors) protoreflect.MessageDescriptor
	findInMessages = func(messages protoreflect.MessageDescriptors) protoreflect.MessageDescriptor {
		for index := 0; index < messages.Len(); index++ {
			message := messages.Get(index)
			if string(message.FullName()) == fullName {
				return message
			}
			if nested := findInMessages(message.Messages()); nested != nil {
				return nested
			}
		}
		return nil
	}
	return findInMessages(file.Messages())
}

type factPathCollector struct {
	macroCalls map[int64]celast.Expr
	aliases    map[string]string
	paths      map[string]struct{}
}

func collectFactAccessPaths(checked *cel.Ast) (paths []string, err error) {
	defer func() {
		if recover() != nil {
			paths = nil
			err = errors.New("CEL fact-access collection panicked while rejecting an expression")
		}
	}()
	if checked == nil || checked.NativeRep() == nil || !checked.IsChecked() {
		return nil, errors.New("cannot collect fact-access paths from an unchecked CEL AST")
	}
	native := checked.NativeRep()
	collector := &factPathCollector{
		macroCalls: native.SourceInfo().MacroCalls(),
		aliases:    make(map[string]string),
		paths:      make(map[string]struct{}),
	}
	if err := collector.walk(native.Expr()); err != nil {
		return nil, err
	}
	paths = make([]string, 0, len(collector.paths))
	for path := range collector.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func (collector *factPathCollector) walk(expression celast.Expr) error {
	if expression == nil || expression.Kind() == celast.UnspecifiedExprKind {
		return errors.New("cannot collect a fact path from an unspecified CEL node")
	}
	if expression.Kind() == celast.ComprehensionKind ||
		(expression.Kind() == celast.SelectKind && expression.AsSelect().IsTestOnly()) {
		if macroCall, ok := collector.macroCalls[expression.ID()]; ok {
			return collector.walkMacro(expression, macroCall)
		}
	}
	switch expression.Kind() {
	case celast.IdentKind, celast.LiteralKind:
		return nil
	case celast.SelectKind:
		path, ok := collector.resolvePath(expression)
		if !ok {
			return errors.New("CEL field selection is not rooted in f or a typed comprehension alias")
		}
		return collector.add(path)
	case celast.CallKind:
		call := expression.AsCall()
		if call.IsMemberFunction() {
			if err := collector.walk(call.Target()); err != nil {
				return err
			}
		}
		for _, argument := range call.Args() {
			if err := collector.walk(argument); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("cannot collect fact paths from CEL AST node kind %d", expression.Kind())
	}
}

func (collector *factPathCollector) walkMacro(expanded celast.Expr, source celast.Expr) error {
	if source.Kind() != celast.CallKind {
		return errors.New("invalid CEL macro source while collecting fact-access paths")
	}
	call := source.AsCall()
	switch call.FunctionName() {
	case operators.Has:
		path, ok := collector.resolvePath(expanded)
		if !ok {
			return errors.New("has() field is not rooted in f")
		}
		return collector.add(path)
	case operators.Exists, operators.All:
		if expanded.Kind() != celast.ComprehensionKind {
			return errors.New("quantifier did not expand to a comprehension")
		}
		comprehension := expanded.AsComprehension()
		receiverPath, ok := collector.resolvePath(comprehension.IterRange())
		if !ok {
			return errors.New("quantifier receiver is not rooted in f or a typed alias")
		}
		if err := collector.add(receiverPath); err != nil {
			return err
		}
		predicate, err := quantifierPredicate(comprehension, call.FunctionName())
		if err != nil {
			return err
		}
		binding := comprehension.IterVar()
		previous, hadPrevious := collector.aliases[binding]
		collector.aliases[binding] = receiverPath
		err = collector.walk(predicate)
		if hadPrevious {
			collector.aliases[binding] = previous
		} else {
			delete(collector.aliases, binding)
		}
		return err
	default:
		return fmt.Errorf("cannot collect fact paths from macro %q", call.FunctionName())
	}
}

func (collector *factPathCollector) resolvePath(expression celast.Expr) (string, bool) {
	switch expression.Kind() {
	case celast.IdentKind:
		name := expression.AsIdent()
		if name == "f" {
			return "", true
		}
		path, ok := collector.aliases[name]
		return path, ok
	case celast.SelectKind:
		selection := expression.AsSelect()
		prefix, ok := collector.resolvePath(selection.Operand())
		if !ok {
			return "", false
		}
		if prefix == "" {
			return selection.FieldName(), true
		}
		return prefix + "." + selection.FieldName(), true
	default:
		return "", false
	}
}

func (collector *factPathCollector) add(path string) error {
	if !validFactAccessPath(path) {
		return fmt.Errorf("invalid or oversized CEL fact-access path %q", path)
	}
	collector.paths[path] = struct{}{}
	return nil
}

func validFactAccessPath(path string) bool {
	if path == "" || len(path) > maxFactAccessPathBytes || !utf8.ValidString(path) {
		return false
	}
	componentStart := true
	for _, character := range path {
		if character == '.' {
			if componentStart {
				return false
			}
			componentStart = true
			continue
		}
		if !((character >= 'a' && character <= 'z') || character == '_' ||
			(!componentStart && character >= '0' && character <= '9')) {
			return false
		}
		componentStart = false
	}
	return !componentStart
}

func quantifierPredicate(comprehension celast.ComprehensionExpr, function string) (celast.Expr, error) {
	step := comprehension.LoopStep()
	if step.Kind() != celast.CallKind || step.AsCall().IsMemberFunction() || len(step.AsCall().Args()) != 2 {
		return nil, fmt.Errorf("%s() expansion has an invalid loop step", function)
	}
	expectedStep := operators.LogicalOr
	expectedInit := false
	if function == operators.All {
		expectedStep = operators.LogicalAnd
		expectedInit = true
	}
	if step.AsCall().FunctionName() != expectedStep {
		return nil, fmt.Errorf("%s() expansion has an invalid loop operator", function)
	}
	accumulator := comprehension.AccuVar()
	stepArgs := step.AsCall().Args()
	if accumulator == "" || accumulator == comprehension.IterVar() ||
		stepArgs[0].Kind() != celast.IdentKind || stepArgs[0].AsIdent() != accumulator {
		return nil, fmt.Errorf("%s() expansion has an invalid accumulator reference", function)
	}
	initial := comprehension.AccuInit()
	if initial.Kind() != celast.LiteralKind {
		return nil, fmt.Errorf("%s() expansion has an invalid accumulator", function)
	}
	initialValue, ok := initial.AsLiteral().(types.Bool)
	if !ok || bool(initialValue) != expectedInit {
		return nil, fmt.Errorf("%s() expansion has an invalid accumulator", function)
	}
	result := comprehension.Result()
	if result.Kind() != celast.IdentKind || result.AsIdent() != comprehension.AccuVar() {
		return nil, fmt.Errorf("%s() expansion has an invalid result", function)
	}
	condition := comprehension.LoopCondition()
	if condition.Kind() != celast.CallKind || condition.AsCall().IsMemberFunction() ||
		condition.AsCall().FunctionName() != operators.NotStrictlyFalse || len(condition.AsCall().Args()) != 1 {
		return nil, fmt.Errorf("%s() expansion has an invalid loop condition", function)
	}
	conditionValue := condition.AsCall().Args()[0]
	if function == operators.Exists {
		if conditionValue.Kind() != celast.CallKind || conditionValue.AsCall().IsMemberFunction() ||
			conditionValue.AsCall().FunctionName() != operators.LogicalNot ||
			len(conditionValue.AsCall().Args()) != 1 {
			return nil, fmt.Errorf("%s() expansion has an invalid short-circuit condition", function)
		}
		conditionValue = conditionValue.AsCall().Args()[0]
	}
	if conditionValue.Kind() != celast.IdentKind || conditionValue.AsIdent() != accumulator {
		return nil, fmt.Errorf("%s() expansion has an invalid short-circuit accumulator", function)
	}
	return stepArgs[1], nil
}

func (validator *subsetValidator) sameType(left celast.Expr, right celast.Expr) bool {
	leftType := validator.checked.GetType(left.ID())
	rightType := validator.checked.GetType(right.ID())
	return leftType.Kind() != types.DynKind && leftType.IsEquivalentType(rightType)
}

func compileExpression(environment *cel.Env, expression string) (
	compiled *cel.Ast,
	issues *cel.Issues,
	err error,
) {
	defer func() {
		if recover() != nil {
			compiled = nil
			issues = nil
			err = errors.New("CEL compiler panicked while rejecting an expression")
		}
	}()
	compiled, issues = environment.Compile(expression)
	return compiled, issues, nil
}

func createProgram(environment *cel.Env, compiled *cel.Ast, options ...cel.ProgramOption) (
	program cel.Program,
	err error,
) {
	defer func() {
		if recover() != nil {
			program = nil
			err = errors.New("CEL program creation panicked while rejecting an expression")
		}
	}()
	return environment.Program(compiled, options...)
}

func verifyCelGoBuildDependency() error {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("Go build metadata is unavailable")
	}
	for _, dependency := range buildInfo.Deps {
		if dependency.Path != "cel.dev/cel-go" {
			continue
		}
		if dependency.Replace != nil {
			return errors.New("cel.dev/cel-go module replacements are not permitted")
		}
		if dependency.Version != celGoVersion {
			return fmt.Errorf("expected cel.dev/cel-go %s, found %s", celGoVersion, dependency.Version)
		}
		return nil
	}
	return errors.New("cel.dev/cel-go module is missing from build metadata")
}

func main() {
	showVersion := flag.Bool("version", false, "print helper and CEL engine versions")
	flag.Parse()
	if err := verifyCelGoBuildDependency(); err != nil {
		fmt.Fprintf(os.Stderr, "cel helper dependency verification failed: %v\n", err)
		os.Exit(1)
	}
	if *showVersion {
		fmt.Printf("skill-scanner-cel-go helper=%s cel-go=%s protocol=%d\n", helperVersion, celGoVersion, protocolVersion)
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), maxFrameBytes)
	writer := bufio.NewWriterSize(os.Stdout, 64*1024)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	server := &runtimeServer{}

	for scanner.Scan() {
		request, err := decodeWireRequest(scanner.Bytes())
		if err != nil {
			response := errorResponse(0, "protocol_error", "PROTOCOL_ERROR", "invalid JSON request")
			if !writeResponse(encoder, writer, response) {
				return
			}
			continue
		}
		response := server.handle(request)
		if !writeResponse(encoder, writer, response) {
			return
		}
		if request.Type == "shutdown" && response.OK {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "cel helper input error: %v\n", err)
	}
}

func decodeWireRequest(raw []byte) (wireRequest, error) {
	request := wireRequest{}
	if !utf8.Valid(raw) {
		return request, errors.New("JSON request is not valid UTF-8")
	}
	if err := validateJSONShape(raw); err != nil {
		return request, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if err := consumeJSONEnd(decoder); err != nil {
		return wireRequest{}, err
	}
	return request, nil
}

func validateJSONShape(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0, true); err != nil {
		return err
	}
	return consumeJSONEnd(decoder)
}

func validateJSONValue(decoder *json.Decoder, depth int, requireObject bool) error {
	if depth > maxJSONNestingDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if requireObject && (!isDelimiter || delimiter != '{') {
		return errors.New("JSON request must be an object")
	}
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder, depth+1, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array closing delimiter")
		}
	default:
		return errors.New("unexpected JSON closing delimiter")
	}
	return nil
}

func consumeJSONEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not permitted")
		}
		return err
	}
	return nil
}

func writeResponse(encoder *json.Encoder, writer *bufio.Writer, response wireResponse) bool {
	if err := encoder.Encode(response); err != nil {
		return false
	}
	return writer.Flush() == nil
}

func (server *runtimeServer) handle(request wireRequest) wireResponse {
	if request.ProtocolVersion != protocolVersion {
		return errorResponse(
			request.RequestID,
			"protocol_error",
			"PROTOCOL_VERSION_MISMATCH",
			fmt.Sprintf("expected protocol version %d", protocolVersion),
		)
	}
	switch request.Type {
	case "initialize":
		return server.initialize(request)
	case "evaluate":
		return server.evaluate(request)
	case "evaluate_batch":
		return server.evaluateBatch(request)
	case "shutdown":
		if !validShutdownRequest(request) {
			return errorResponse(
				request.RequestID,
				"shutdown",
				"INVALID_SHUTDOWN_REQUEST",
				"shutdown request contains unrelated fields",
			)
		}
		return wireResponse{
			ProtocolVersion: protocolVersion,
			Type:            "shutdown",
			RequestID:       request.RequestID,
			OK:              true,
		}
	default:
		return errorResponse(request.RequestID, "protocol_error", "UNKNOWN_REQUEST_TYPE", "unknown request type")
	}
}

func validShutdownRequest(request wireRequest) bool {
	return request.ExpressionSetHash == "" && request.DescriptorB64 == "" && len(request.Rules) == 0 &&
		request.RuleID == "" && request.FactsB64 == "" && len(request.Items) == 0 &&
		request.EvalTimeoutMS == 0 && request.CostLimit == 0
}

func (server *runtimeServer) initialize(request wireRequest) wireResponse {
	if len(request.Rules) > maxRules {
		return errorResponse(request.RequestID, "initialized", "RULE_COUNT_LIMIT", "invalid CEL rule count")
	}
	if (len(request.Rules) == 0 && request.ExpressionSetHash != "") ||
		(len(request.Rules) > 0 && !isSHA256(request.ExpressionSetHash)) {
		return errorResponse(request.RequestID, "initialized", "EXPRESSION_HASH_INVALID", "invalid expression-set hash")
	}

	descriptorBytes, err := decodeBoundedBase64(request.DescriptorB64, maxDescriptorBytes)
	if err != nil {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", err.Error())
	}
	descriptorDigest := sha256.Sum256(descriptorBytes)
	descriptorHash := hex.EncodeToString(descriptorDigest[:])
	if descriptorHash != canonicalDescriptorHash {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_HASH_MISMATCH", "non-canonical ScanFacts descriptor")
	}
	descriptorSet := &descriptorpb.FileDescriptorSet{}
	if err := (proto.UnmarshalOptions{RecursionLimit: maxProtoRecursionDepth}).Unmarshal(
		descriptorBytes,
		descriptorSet,
	); err != nil {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", "invalid descriptor set")
	}
	if len(descriptorSet.File) == 0 || len(descriptorSet.File) > maxDescriptorFiles {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", "invalid descriptor file count")
	}
	files, err := protodesc.NewFiles(descriptorSet)
	if err != nil {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", boundedMessage(err))
	}
	descriptor, err := files.FindDescriptorByName(protoreflect.FullName(scanFactsType))
	if err != nil {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", "ScanFacts descriptor not found")
	}
	messageDescriptor, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		return errorResponse(request.RequestID, "initialized", "DESCRIPTOR_INVALID", "ScanFacts is not a message")
	}

	environment, err := newSkillScannerCELEnv(descriptorSet)
	if err != nil {
		return errorResponse(request.RequestID, "initialized", "ENVIRONMENT_ERROR", boundedMessage(err))
	}

	computedHash, err := expressionSetHash(request.Rules)
	if err != nil {
		return errorResponse(request.RequestID, "initialized", "RULE_INVALID", err.Error())
	}
	if computedHash != request.ExpressionSetHash {
		return errorResponse(request.RequestID, "initialized", "EXPRESSION_HASH_MISMATCH", "expression-set hash mismatch")
	}

	timeoutMillis := request.EvalTimeoutMS
	if timeoutMillis == 0 {
		timeoutMillis = defaultEvalTimeoutMillis
	}
	if timeoutMillis > maxEvalTimeoutMillis {
		return errorResponse(request.RequestID, "initialized", "EVAL_TIMEOUT_LIMIT", "evaluation timeout exceeds limit")
	}
	costLimit := request.CostLimit
	if costLimit == 0 {
		costLimit = defaultCostLimit
	}
	if costLimit > maxCostLimit {
		return errorResponse(request.RequestID, "initialized", "COST_LIMIT_INVALID", "evaluation cost limit exceeds maximum")
	}

	programs := make(map[string]cel.Program, len(request.Rules))
	factAccessPaths := make(map[string][]string, len(request.Rules))
	totalExpressionNodes := 0
	totalFactAccessPaths := 0
	totalFactAccessBytes := 0
	for _, rule := range request.Rules {
		ast, issues, compileErr := compileExpression(environment, rule.Expression)
		if compileErr != nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_COMPILE_ERROR",
				fmt.Sprintf("CEL compiler failure in %s: %s", rule.RuleID, boundedMessage(compileErr)),
			)
		}
		if issues != nil && issues.Err() != nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_COMPILE_ERROR",
				fmt.Sprintf("CEL compile/type error in %s: %s", rule.RuleID, boundedMessage(issues.Err())),
			)
		}
		if ast == nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_COMPILE_ERROR",
				fmt.Sprintf("CEL compiler returned no AST for %s", rule.RuleID),
			)
		}
		if ast.OutputType() != cel.BoolType {
			return errorResponse(
				request.RequestID,
				"initialized",
				"NON_BOOLEAN_EXPRESSION",
				fmt.Sprintf("CEL expression for %s must return bool", rule.RuleID),
			)
		}
		nodeCount, err := validateExpressionSubset(ast, messageDescriptor)
		if err != nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_SUBSET_ERROR",
				fmt.Sprintf("CEL subset error in %s: %s", rule.RuleID, boundedMessage(err)),
			)
		}
		totalExpressionNodes += nodeCount
		if totalExpressionNodes > maxTotalExpressionNodes {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_GENERATION_NODE_LIMIT",
				"CEL generation exceeds total AST node limit",
			)
		}
		paths, err := collectFactAccessPaths(ast)
		if err != nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_FACT_PATH_ERROR",
				fmt.Sprintf("CEL fact-access error in %s: %s", rule.RuleID, boundedMessage(err)),
			)
		}
		totalFactAccessPaths += len(paths)
		for _, path := range paths {
			totalFactAccessBytes += len(path)
		}
		if totalFactAccessPaths > maxFactAccessPaths || totalFactAccessBytes > maxTotalFactAccessBytes {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_FACT_PATH_LIMIT",
				"CEL generation exceeds fact-access path limits",
			)
		}
		factAccessPaths[rule.RuleID] = paths
		program, err := createProgram(
			environment,
			ast,
			cel.EvalOptions(cel.OptOptimize),
			cel.CostLimit(costLimit),
			cel.InterruptCheckFrequency(interruptCheckFrequency),
		)
		if err != nil {
			return errorResponse(
				request.RequestID,
				"initialized",
				"CEL_PROGRAM_ERROR",
				fmt.Sprintf("CEL program error in %s: %s", rule.RuleID, boundedMessage(err)),
			)
		}
		programs[rule.RuleID] = program
	}

	newGeneration := &compiledGeneration{
		programs:          programs,
		messageDescriptor: messageDescriptor,
		expressionSetHash: computedHash,
		descriptorHash:    descriptorHash,
		evalTimeout:       time.Duration(timeoutMillis) * time.Millisecond,
		factAccessPaths:   factAccessPaths,
	}
	// Publish only after every expression has compiled and type-checked.
	server.generation = newGeneration
	return wireResponse{
		ProtocolVersion:   protocolVersion,
		Type:              "initialized",
		RequestID:         request.RequestID,
		OK:                true,
		Runtime:           runtimeName,
		RuntimeVersion:    celGoVersion,
		HelperVersion:     helperVersion,
		ExpressionSetHash: computedHash,
		DescriptorHash:    newGeneration.descriptorHash,
		RuleCount:         len(programs),
		FactAccessPaths:   &newGeneration.factAccessPaths,
	}
}

func (server *runtimeServer) evaluate(request wireRequest) wireResponse {
	generation := server.generation
	if generation == nil {
		return errorResponse(request.RequestID, "evaluation", "NOT_INITIALIZED", "runtime is not initialized")
	}
	if len(request.Items) != 0 || len(request.Rules) != 0 || request.DescriptorB64 != "" ||
		request.EvalTimeoutMS != 0 || request.CostLimit != 0 {
		response := errorResponse(request.RequestID, "evaluation", "ACTIVATION_INVALID", "invalid evaluation request")
		response.ExpressionSetHash = generation.expressionSetHash
		return response
	}
	if request.ExpressionSetHash != generation.expressionSetHash {
		response := errorResponse(request.RequestID, "evaluation", "GENERATION_MISMATCH", "expression generation mismatch")
		response.ExpressionSetHash = generation.expressionSetHash
		return response
	}
	result := generation.evaluateItem(request.RuleID, request.FactsB64)
	if !result.OK {
		response := errorResponse(request.RequestID, "evaluation", result.ErrorCode, "CEL evaluation failed open")
		response.ElapsedMS = result.ElapsedMS
		response.ActualCost = result.ActualCost
		response.ExpressionSetHash = generation.expressionSetHash
		return response
	}
	return wireResponse{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluation",
		RequestID:         request.RequestID,
		OK:                true,
		Value:             result.Value,
		ElapsedMS:         result.ElapsedMS,
		ActualCost:        result.ActualCost,
		ExpressionSetHash: generation.expressionSetHash,
	}
}

func (server *runtimeServer) evaluateBatch(request wireRequest) wireResponse {
	generation := server.generation
	if generation == nil {
		return errorResponse(request.RequestID, "batch_evaluation", "NOT_INITIALIZED", "runtime is not initialized")
	}
	if request.ExpressionSetHash != generation.expressionSetHash {
		response := errorResponse(
			request.RequestID,
			"batch_evaluation",
			"GENERATION_MISMATCH",
			"expression generation mismatch",
		)
		response.ExpressionSetHash = generation.expressionSetHash
		return response
	}
	if len(request.Items) == 0 || len(request.Items) > maxBatchItems || request.RuleID != "" ||
		request.FactsB64 != "" || len(request.Rules) != 0 || request.DescriptorB64 != "" ||
		request.EvalTimeoutMS != 0 || request.CostLimit != 0 {
		response := errorResponse(request.RequestID, "batch_evaluation", "BATCH_ITEM_LIMIT", "invalid batch request")
		response.ExpressionSetHash = generation.expressionSetHash
		return response
	}
	totalDecodedBytes := 0
	for _, item := range request.Items {
		totalDecodedBytes += base64.StdEncoding.DecodedLen(len(item.FactsB64))
		if totalDecodedBytes > maxBatchFactsBytes {
			response := errorResponse(
				request.RequestID,
				"batch_evaluation",
				"ACTIVATION_BATCH_SIZE_LIMIT",
				"batch activations exceed total size limit",
			)
			response.ExpressionSetHash = generation.expressionSetHash
			return response
		}
	}

	started := time.Now()
	results := make([]wireBatchResult, 0, len(request.Items))
	for _, item := range request.Items {
		results = append(results, generation.evaluateItem(item.RuleID, item.FactsB64))
	}
	return wireResponse{
		ProtocolVersion:   protocolVersion,
		Type:              "batch_evaluation",
		RequestID:         request.RequestID,
		OK:                true,
		ElapsedMS:         float64(time.Since(started).Nanoseconds()) / float64(time.Millisecond),
		ExpressionSetHash: generation.expressionSetHash,
		Results:           &results,
	}
}

func (generation *compiledGeneration) evaluateItem(ruleID string, factsB64 string) wireBatchResult {
	program, ok := generation.programs[ruleID]
	if !ok {
		return wireBatchResult{OK: false, ErrorCode: "UNKNOWN_RULE_ID"}
	}
	factsBytes, err := decodeBoundedBase64(factsB64, maxFactsBytes)
	if err != nil {
		return wireBatchResult{OK: false, ErrorCode: "ACTIVATION_INVALID"}
	}
	facts := dynamicpb.NewMessage(generation.messageDescriptor)
	if err := (proto.UnmarshalOptions{RecursionLimit: maxProtoRecursionDepth}).Unmarshal(factsBytes, facts); err != nil {
		return wireBatchResult{OK: false, ErrorCode: "ACTIVATION_INVALID"}
	}
	if code := validateActivation(facts, ruleID, len(factsBytes)); code != "" {
		return wireBatchResult{OK: false, ErrorCode: code}
	}

	started := time.Now()
	value, actualCost, errorCode := evaluateProgram(program, facts, generation.evalTimeout)
	elapsedMillis := float64(time.Since(started).Nanoseconds()) / float64(time.Millisecond)
	if errorCode != "" {
		return wireBatchResult{
			OK:         false,
			ElapsedMS:  elapsedMillis,
			ActualCost: actualCost,
			ErrorCode:  errorCode,
		}
	}
	return wireBatchResult{
		OK:         true,
		Value:      &value,
		ElapsedMS:  elapsedMillis,
		ActualCost: actualCost,
	}
}

func evaluateProgram(program cel.Program, facts proto.Message, timeout time.Duration) (
	value bool,
	actualCost uint64,
	errorCode string,
) {
	defer func() {
		if recover() != nil {
			value = false
			errorCode = "EVALUATION_PANIC"
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, details, err := program.ContextEval(ctx, map[string]any{"f": facts})
	if details != nil && details.ActualCost() != nil {
		actualCost = *details.ActualCost()
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, actualCost, "EVALUATION_TIMEOUT"
	}
	if err != nil {
		var cancelled interpreter.EvalCancelledError
		if errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded {
			return false, actualCost, "EVALUATION_COST_LIMIT"
		}
		return false, actualCost, "EVALUATION_ERROR"
	}
	boolValue, ok := result.(types.Bool)
	if !ok {
		return false, actualCost, "NON_BOOLEAN_RESULT"
	}
	return bool(boolValue), actualCost, ""
}

func validateActivation(facts protoreflect.ProtoMessage, ruleID string, serializedBytes int) string {
	message := facts.ProtoReflect()
	if hasUnknownFields(message, 0) {
		return "ACTIVATION_UNKNOWN_FIELDS"
	}
	if !validateMessageBounds(message, 0) {
		return "ACTIVATION_FACT_LIMIT"
	}
	schemaField := message.Descriptor().Fields().ByName("schema_version")
	if schemaField == nil || message.Get(schemaField).String() != supportedFactSchema {
		return "FACT_SCHEMA_MISMATCH"
	}
	candidateField := message.Descriptor().Fields().ByName("candidate")
	if candidateField == nil || candidateField.Message() == nil || !message.Has(candidateField) {
		return "ACTIVATION_INVALID"
	}
	candidate := message.Get(candidateField).Message()
	ruleField := candidate.Descriptor().Fields().ByName("rule_id")
	if ruleField == nil || candidate.Get(ruleField).String() != ruleID {
		return "CANDIDATE_RULE_MISMATCH"
	}
	projectionField := message.Descriptor().Fields().ByName("projection")
	if projectionField == nil || projectionField.Message() == nil || !message.Has(projectionField) {
		return "ACTIVATION_INVALID"
	}
	projection := message.Get(projectionField).Message()
	completeField := projection.Descriptor().Fields().ByName("complete")
	errorCodesField := projection.Descriptor().Fields().ByName("error_codes")
	serializedBytesField := projection.Descriptor().Fields().ByName("serialized_bytes")
	truncatedField := projection.Descriptor().Fields().ByName("truncated")
	if completeField == nil || !projection.Get(completeField).Bool() {
		return "PROJECTION_INCOMPLETE"
	}
	if errorCodesField == nil || projection.Get(errorCodesField).List().Len() != 0 {
		return "PROJECTION_INCOMPLETE"
	}
	if truncatedField == nil || projection.Get(truncatedField).Bool() {
		return "PROJECTION_INCOMPLETE"
	}
	if serializedBytesField == nil || projection.Get(serializedBytesField).Uint() != uint64(serializedBytes) {
		return "SERIALIZED_SIZE_MISMATCH"
	}

	skillField := message.Descriptor().Fields().ByName("skill")
	if skillField == nil || skillField.Message() == nil || !message.Has(skillField) {
		return "ACTIVATION_INVALID"
	}
	skill := message.Get(skillField).Message()
	filesField := skill.Descriptor().Fields().ByName("files")
	if filesField == nil || skill.Get(filesField).List().Len() > maxFiles {
		return "FILE_FACT_LIMIT"
	}
	semanticCount := 0
	for _, fieldName := range []protoreflect.Name{"commands", "urls", "flows", "reference_edges", "signals"} {
		field := skill.Descriptor().Fields().ByName(fieldName)
		if field == nil {
			return "ACTIVATION_INVALID"
		}
		semanticCount += skill.Get(field).List().Len()
	}
	if semanticCount > maxSemanticItems {
		return "SEMANTIC_FACT_LIMIT"
	}
	return ""
}

func hasUnknownFields(message protoreflect.Message, depth int) bool {
	if !message.IsValid() || depth > maxProtoRecursionDepth || len(message.GetUnknown()) != 0 {
		return true
	}
	fields := message.Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.Kind() != protoreflect.MessageKind {
			continue
		}
		value := message.Get(field)
		if field.IsList() {
			list := value.List()
			for itemIndex := 0; itemIndex < list.Len(); itemIndex++ {
				if hasUnknownFields(list.Get(itemIndex).Message(), depth+1) {
					return true
				}
			}
			continue
		}
		if message.Has(field) && hasUnknownFields(value.Message(), depth+1) {
			return true
		}
	}
	return false
}

func validateMessageBounds(message protoreflect.Message, depth int) bool {
	if !message.IsValid() || depth > maxProtoRecursionDepth || len(message.GetUnknown()) != 0 {
		return false
	}
	fields := message.Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		value := message.Get(field)
		if field.IsMap() {
			return false
		}
		if field.IsList() {
			list := value.List()
			if list.Len() > maxRepeatedItems {
				return false
			}
			for itemIndex := 0; itemIndex < list.Len(); itemIndex++ {
				item := list.Get(itemIndex)
				if field.Kind() == protoreflect.StringKind && len(item.String()) > maxStringBytes {
					return false
				}
				if field.Kind() == protoreflect.MessageKind && !validateMessageBounds(item.Message(), depth+1) {
					return false
				}
			}
			continue
		}
		if field.Kind() == protoreflect.StringKind && len(value.String()) > maxStringBytes {
			return false
		}
		if field.Kind() == protoreflect.MessageKind && message.Has(field) &&
			!validateMessageBounds(value.Message(), depth+1) {
			return false
		}
	}
	return true
}

func expressionSetHash(rules []wireRule) (string, error) {
	if len(rules) == 0 {
		return "", nil
	}
	ordered := append([]wireRule(nil), rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].RuleID < ordered[j].RuleID })
	digest := sha256.New()
	digest.Write([]byte("skill-scanner-cel-expression-set-v1\x00"))
	seen := make(map[string]struct{}, len(ordered))
	totalExpressionBytes := 0
	for _, rule := range ordered {
		if rule.RuleID == "" || len(rule.RuleID) > maxRuleIDBytes {
			return "", fmt.Errorf("invalid CEL rule ID")
		}
		if _, exists := seen[rule.RuleID]; exists {
			return "", fmt.Errorf("duplicate CEL rule ID")
		}
		seen[rule.RuleID] = struct{}{}
		if rule.FactSchema != supportedFactSchema {
			return "", fmt.Errorf("unsupported CEL fact schema")
		}
		if !utf8.ValidString(rule.Expression) || len(rule.Expression) == 0 || len(rule.Expression) > maxExpressionBytes ||
			utf8.RuneCountInString(rule.Expression) > maxExpressionBytes {
			return "", fmt.Errorf("CEL expression exceeds size limit")
		}
		totalExpressionBytes += len(rule.Expression)
		if totalExpressionBytes > maxTotalExpressionBytes {
			return "", fmt.Errorf("CEL generation exceeds total expression limit")
		}
		writeHashField(digest, rule.RuleID)
		writeHashField(digest, rule.FactSchema)
		writeHashField(digest, rule.Expression)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeHashField(digest hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	digest.Write(length[:])
	digest.Write([]byte(value))
}

func decodeBoundedBase64(encoded string, maxDecodedBytes int) ([]byte, error) {
	if encoded == "" || base64.StdEncoding.DecodedLen(len(encoded)) > maxDecodedBytes {
		return nil, fmt.Errorf("encoded payload exceeds size limit")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload")
	}
	if len(decoded) > maxDecodedBytes {
		return nil, fmt.Errorf("decoded payload exceeds size limit")
	}
	return decoded, nil
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func errorResponse(requestID uint64, responseType string, code string, message string) wireResponse {
	return wireResponse{
		ProtocolVersion: protocolVersion,
		Type:            responseType,
		RequestID:       requestID,
		OK:              false,
		ErrorCode:       code,
		Message:         message,
	}
}

func boundedMessage(err error) string {
	message := err.Error()
	if len(message) > 2048 {
		return message[:2048]
	}
	return message
}
