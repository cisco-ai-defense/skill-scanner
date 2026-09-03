// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

type deadlineSuccessProgram struct{}

func (deadlineSuccessProgram) Eval(any) (ref.Val, *cel.EvalDetails, error) {
	return types.True, nil, nil
}

func (deadlineSuccessProgram) ContextEval(ctx context.Context, _ any) (ref.Val, *cel.EvalDetails, error) {
	<-ctx.Done()
	return types.True, nil, nil
}

func (deadlineSuccessProgram) ConcurrentEval(context.Context, any) <-chan cel.EvalResult {
	return nil
}

type costCancelledProgram struct{}

func (costCancelledProgram) Eval(any) (ref.Val, *cel.EvalDetails, error) {
	return nil, nil, interpreter.EvalCancelledError{
		Cause:   interpreter.CostLimitExceeded,
		Message: "opaque typed cancellation",
	}
}

func (costCancelledProgram) ContextEval(context.Context, any) (ref.Val, *cel.EvalDetails, error) {
	return costCancelledProgram{}.Eval(nil)
}

func (costCancelledProgram) ConcurrentEval(context.Context, any) <-chan cel.EvalResult {
	return nil
}

func testDescriptorSet(t *testing.T) (*descriptorpb.FileDescriptorSet, protoreflect.MessageDescriptor) {
	t.Helper()
	encoded, err := os.ReadFile("testdata/scan_facts_descriptor.b64")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("base64.DecodeString() error = %v", err)
	}
	set := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, set); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		t.Fatalf("protodesc.NewFiles() error = %v", err)
	}
	descriptor, err := files.FindDescriptorByName(scanFactsType)
	if err != nil {
		t.Fatalf("FindDescriptorByName() error = %v", err)
	}
	messageDescriptor, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatal("ScanFacts descriptor is not a message")
	}
	return set, messageDescriptor
}

func encodedDescriptor(t *testing.T, set *descriptorpb.FileDescriptorSet) string {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(set)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func initRequest(t *testing.T, rules []wireRule) wireRequest {
	t.Helper()
	set, _ := testDescriptorSet(t)
	digest, err := expressionSetHash(rules)
	if err != nil {
		t.Fatalf("expressionSetHash() error = %v", err)
	}
	return wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "initialize",
		RequestID:         1,
		ExpressionSetHash: digest,
		DescriptorB64:     encodedDescriptor(t, set),
		Rules:             rules,
	}
}

func encodedFacts(t *testing.T, descriptor protoreflect.MessageDescriptor, ruleID string, value bool) string {
	t.Helper()
	message := dynamicpb.NewMessage(descriptor)
	schemaField := descriptor.Fields().ByName("schema_version")
	message.Set(schemaField, protoreflect.ValueOfString(supportedFactSchema))
	skillField := descriptor.Fields().ByName("skill")
	skill := message.Mutable(skillField).Message()
	skill.Set(skill.Descriptor().Fields().ByName("has_description"), protoreflect.ValueOfBool(value))
	candidateField := descriptor.Fields().ByName("candidate")
	candidate := message.Mutable(candidateField).Message()
	candidate.Set(candidate.Descriptor().Fields().ByName("rule_id"), protoreflect.ValueOfString(ruleID))
	projectionField := descriptor.Fields().ByName("projection")
	projection := message.Mutable(projectionField).Message()
	projection.Set(projection.Descriptor().Fields().ByName("complete"), protoreflect.ValueOfBool(true))
	serializedBytesField := projection.Descriptor().Fields().ByName("serialized_bytes")
	var raw []byte
	for range 8 {
		var err error
		raw, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatalf("proto.Marshal() error = %v", err)
		}
		if projection.Get(serializedBytesField).Uint() == uint64(len(raw)) {
			break
		}
		projection.Set(serializedBytesField, protoreflect.ValueOfUint64(uint64(len(raw))))
	}
	raw, _ = proto.MarshalOptions{Deterministic: true}.Marshal(message)
	return base64.StdEncoding.EncodeToString(raw)
}

func mutateEncodedFacts(
	t *testing.T,
	descriptor protoreflect.MessageDescriptor,
	ruleID string,
	mutate func(*dynamicpb.Message),
) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encodedFacts(t, descriptor, ruleID, true))
	if err != nil {
		t.Fatalf("base64.DecodeString() error = %v", err)
	}
	message := dynamicpb.NewMessage(descriptor)
	if err := proto.Unmarshal(raw, message); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	mutate(message)
	projectionField := descriptor.Fields().ByName("projection")
	if message.Has(projectionField) {
		projection := message.Get(projectionField).Message()
		serializedBytesField := projection.Descriptor().Fields().ByName("serialized_bytes")
		for range 8 {
			raw, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
			if err != nil {
				t.Fatalf("proto.Marshal() error = %v", err)
			}
			if projection.Get(serializedBytesField).Uint() == uint64(len(raw)) {
				break
			}
			projection.Set(serializedBytesField, protoreflect.ValueOfUint64(uint64(len(raw))))
		}
	}
	raw, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestInitializeAndEvaluateTypedFacts(t *testing.T) {
	rules := []wireRule{{
		RuleID:     "RULE",
		Expression: `f.schema_version == "v1" && f.projection.complete && f.skill.has_description`,
		FactSchema: supportedFactSchema,
	}}
	server := &runtimeServer{}
	response := server.handle(initRequest(t, rules))
	if !response.OK || response.RuntimeVersion != celGoVersion || response.ExpressionSetHash == "" {
		t.Fatalf("initialize response = %#v", response)
	}
	_, descriptor := testDescriptorSet(t)
	for _, value := range []bool{true, false} {
		response = server.handle(wireRequest{
			ProtocolVersion:   protocolVersion,
			Type:              "evaluate",
			RequestID:         2,
			ExpressionSetHash: response.ExpressionSetHash,
			RuleID:            "RULE",
			FactsB64:          encodedFacts(t, descriptor, "RULE", value),
		})
		if !response.OK || response.Value == nil || *response.Value != value {
			t.Fatalf("evaluation response = %#v, want %v", response, value)
		}
	}
}

func TestEvaluateBatchPreservesOrderAndPerItemErrors(t *testing.T) {
	rules := []wireRule{
		{RuleID: "KEEP", Expression: "f.skill.has_description", FactSchema: supportedFactSchema},
		{RuleID: "DROP", Expression: "f.skill.has_description", FactSchema: supportedFactSchema},
	}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	_, descriptor := testDescriptorSet(t)
	response := server.handle(wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluate_batch",
		RequestID:         2,
		ExpressionSetHash: initialized.ExpressionSetHash,
		Items: []wireBatchItem{
			{RuleID: "KEEP", FactsB64: encodedFacts(t, descriptor, "KEEP", true)},
			{RuleID: "DROP", FactsB64: encodedFacts(t, descriptor, "DROP", false)},
			{RuleID: "MISSING", FactsB64: encodedFacts(t, descriptor, "MISSING", true)},
		},
	})
	if !response.OK || response.Results == nil || len(*response.Results) != 3 {
		t.Fatalf("batch response = %#v", response)
	}
	results := *response.Results
	if !results[0].OK || results[0].Value == nil || !*results[0].Value {
		t.Fatalf("first result = %#v", results[0])
	}
	if !results[1].OK || results[1].Value == nil || *results[1].Value {
		t.Fatalf("second result = %#v", results[1])
	}
	if results[2].OK || results[2].ErrorCode != "UNKNOWN_RULE_ID" {
		t.Fatalf("third result = %#v", results[2])
	}
}

func TestEvaluateBatchRejectsOversizedGenerationAtomically(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	items := make([]wireBatchItem, maxBatchItems+1)
	response := server.handle(wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluate_batch",
		RequestID:         2,
		ExpressionSetHash: initialized.ExpressionSetHash,
		Items:             items,
	})
	if response.OK || response.ErrorCode != "BATCH_ITEM_LIMIT" || response.Results != nil {
		t.Fatalf("oversized batch response = %#v", response)
	}
}

func TestFailedGenerationDoesNotReplaceCompiledGeneration(t *testing.T) {
	validRules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	if response := server.handle(initRequest(t, validRules)); !response.OK {
		t.Fatalf("valid initialize response = %#v", response)
	}
	original := server.generation
	invalidRules := []wireRule{{RuleID: "BROKEN", Expression: "f.no_such_field", FactSchema: supportedFactSchema}}
	response := server.handle(initRequest(t, invalidRules))
	if response.OK || response.ErrorCode != "CEL_COMPILE_ERROR" {
		t.Fatalf("invalid initialize response = %#v", response)
	}
	if server.generation != original {
		t.Fatal("failed generation replaced the active generation")
	}
}

func TestNonBooleanExpressionIsRejected(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.schema_version", FactSchema: supportedFactSchema}}
	response := (&runtimeServer{}).handle(initRequest(t, rules))
	if response.OK || response.ErrorCode != "NON_BOOLEAN_EXPRESSION" {
		t.Fatalf("initialize response = %#v", response)
	}
}

func TestApprovedCELSubsetCompiles(t *testing.T) {
	expressions := []string{
		`f.schema_version == "v1" && f.projection.complete`,
		`!f.skill.has_description || has(f.candidate.file)`,
		`f.skill.file_count >= 2u && f.skill.total_bytes != 0u`,
		`"curl" in f.skill.declared_tools`,
		`f.skill.name.startsWith("safe-") || f.skill.name.endsWith("-safe")`,
		`f.skill.name.contains("safe") || f.skill.name.matches("^safe[-a-z]*$")`,
		`f.skill.name.matches("^\\d{1,4}$")`,
		`f.skill.files.exists(file, file.hidden && file.path.contains("/."))`,
		`f.skill.files.all(file, !file.executable || file.referenced)`,
		`f.skill.files.exists(outer, f.skill.files.all(inner, outer.path != inner.path))`,
		`f.skill.files.exists(file, file.hidden && has(f.candidate.file))`,
	}
	for index, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			rules := []wireRule{{
				RuleID:     "RULE",
				Expression: expression,
				FactSchema: supportedFactSchema,
			}}
			response := (&runtimeServer{}).handle(initRequest(t, rules))
			if !response.OK {
				t.Fatalf("approved expression %d failed initialization: %#v", index, response)
			}
		})
	}
}

func TestInitializationReturnsCompilerDerivedFactAccessPaths(t *testing.T) {
	rules := []wireRule{
		{
			RuleID: "COMMAND",
			Expression: `f.skill.commands.exists(command,
                command.source_class == "secret" &&
                command.argument_classes.exists(argument, argument == "encoded"))`,
			FactSchema: supportedFactSchema,
		},
		{
			RuleID:     "FILE",
			Expression: `has(f.candidate.file) && f.candidate.file.executable`,
			FactSchema: supportedFactSchema,
		},
	}
	response := (&runtimeServer{}).handle(initRequest(t, rules))
	if !response.OK || response.FactAccessPaths == nil {
		t.Fatalf("initialize response = %#v", response)
	}
	want := map[string][]string{
		"COMMAND": {
			"skill.commands",
			"skill.commands.argument_classes",
			"skill.commands.source_class",
		},
		"FILE": {"candidate.file", "candidate.file.executable"},
	}
	got := *response.FactAccessPaths
	if len(got) != len(want) {
		t.Fatalf("fact-access rule count = %d, want %d: %#v", len(got), len(want), got)
	}
	for ruleID, wantPaths := range want {
		if strings.Join(got[ruleID], "|") != strings.Join(wantPaths, "|") {
			t.Fatalf("fact-access paths for %s = %v, want %v", ruleID, got[ruleID], wantPaths)
		}
	}
}

func TestSuccessfulEmptyGenerationIncludesFactAccessMappingOnlyOnSuccess(t *testing.T) {
	response := (&runtimeServer{}).handle(initRequest(t, nil))
	if !response.OK || response.FactAccessPaths == nil || len(*response.FactAccessPaths) != 0 {
		t.Fatalf("initialize response = %#v", response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(encoded), `"fact_access_paths":{}`) {
		t.Fatalf("successful response omitted empty fact-access mapping: %s", encoded)
	}
	errorEncoded, err := json.Marshal(errorResponse(1, "initialized", "FAIL", "failed"))
	if err != nil {
		t.Fatalf("json.Marshal(error response) error = %v", err)
	}
	if strings.Contains(string(errorEncoded), "fact_access_paths") {
		t.Fatalf("error response exposed fact-access mapping: %s", errorEncoded)
	}
}

func TestCELSubsetRejectsUnsupportedLanguageFeatures(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{name: "arithmetic", expression: `f.skill.file_count + 1u > 2u`},
		{name: "indexing", expression: `f.skill.files[0].hidden`},
		{name: "list construction", expression: `f.skill.file_count in [1u, 2u]`},
		{name: "map construction", expression: `f.skill.name in {"name": true}`},
		{
			name:       "message construction",
			expression: `skill_scanner.semantic.v1.FileFact{path: "x"}.path == f.skill.name`,
		},
		{name: "conditional", expression: `f.skill.has_description ? true : false`},
		{name: "custom function", expression: `size(f.skill.files) > 0`},
		{name: "conversion function", expression: `string(f.skill.file_count) == f.skill.name`},
		{name: "unsupported method", expression: `f.skill.name.lowerAscii() == "safe"`},
		{name: "exists one macro", expression: `f.skill.files.exists_one(file, file.hidden)`},
		{name: "map macro", expression: `f.skill.files.map(file, file.path).exists(path, path == "x")`},
		{name: "filter macro", expression: `f.skill.files.filter(file, file.hidden).exists(file, true)`},
		{name: "bytes literal", expression: `f.skill.name == "x" && b"x" == b"x"`},
		{name: "scalar presence test", expression: `has(f.skill.name)`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules := []wireRule{{RuleID: "RULE", Expression: test.expression, FactSchema: supportedFactSchema}}
			response := (&runtimeServer{}).handle(initRequest(t, rules))
			if response.OK {
				t.Fatalf("unsupported CEL expression initialized successfully: %s", test.expression)
			}
			if response.ErrorCode != "CEL_COMPILE_ERROR" && response.ErrorCode != "CEL_SUBSET_ERROR" {
				t.Fatalf("unexpected rejection for %s: %#v", test.expression, response)
			}
		})
	}
}

func TestCELSubsetRejectsUnsafeButWellTypedExpressions(t *testing.T) {
	tests := []struct {
		name       string
		expression string
	}{
		{name: "missing typed root", expression: `"same" == "same"`},
		{name: "dynamic contains argument", expression: `f.skill.name.contains(f.candidate.rule_id)`},
		{name: "dynamic matches argument", expression: `f.skill.name.matches(f.candidate.rule_id)`},
		{name: "root shadow", expression: `f.skill.files.exists(f, f.hidden)`},
		{name: "cross numeric comparison", expression: `f.skill.file_count > 0`},
		{name: "bool ordering", expression: `f.skill.has_description < true`},
		{name: "map membership", expression: `f.skill.name in {"name": true}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules := []wireRule{{RuleID: "RULE", Expression: test.expression, FactSchema: supportedFactSchema}}
			response := (&runtimeServer{}).handle(initRequest(t, rules))
			if response.OK ||
				(response.ErrorCode != "CEL_SUBSET_ERROR" && response.ErrorCode != "CEL_COMPILE_ERROR") {
				t.Fatalf("initialize response for %q = %#v", test.expression, response)
			}
		})
	}
}

func TestCELSubsetBoundsComprehensionsAndLiteralRegex(t *testing.T) {
	threeDeep := `f.skill.files.exists(a, f.skill.files.exists(b, f.skill.files.exists(c, a.path == b.path && b.path == c.path)))`
	tooLongRegex := `f.skill.name.matches("` + strings.Repeat("a", maxLiteralRegexChars+1) + `")`
	tooLargeRegexProgram := `f.skill.name.matches("(?:a{1000}){5}")`
	for _, test := range []struct {
		name       string
		expression string
	}{
		{name: "three nested comprehensions", expression: threeDeep},
		{name: "regex over 512 characters", expression: tooLongRegex},
		{name: "regex program over instruction limit", expression: tooLargeRegexProgram},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := []wireRule{{RuleID: "RULE", Expression: test.expression, FactSchema: supportedFactSchema}}
			response := (&runtimeServer{}).handle(initRequest(t, rules))
			if response.OK || response.ErrorCode != "CEL_SUBSET_ERROR" {
				t.Fatalf("initialize response = %#v", response)
			}
		})
	}
}

func TestLiteralRegexValidatorHandlesBoundedRepeatsWithoutPanic(t *testing.T) {
	if err := validateLiteralRegex(`^\d{1,4}$`); err != nil {
		t.Fatalf("validateLiteralRegex() rejected a bounded repeat: %v", err)
	}
	if err := validateLiteralRegex(`(?:a{1000}){5}`); err == nil {
		t.Fatal("validateLiteralRegex() accepted a program over the instruction limit")
	}
	for _, invalid := range []string{`(?=lookahead)`, `(a)\1`, `a{1001}`} {
		if err := validateLiteralRegex(invalid); err == nil {
			t.Fatalf("validateLiteralRegex(%q) accepted an unsupported RE2 pattern", invalid)
		}
	}
}

func TestBoundedRepeatRegexEvaluatesWithoutPanic(t *testing.T) {
	rules := []wireRule{{
		RuleID:     "REGEX",
		Expression: `f.skill.name.matches("a{1,4}")`,
		FactSchema: supportedFactSchema,
	}}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	_, descriptor := testDescriptorSet(t)
	evaluated := server.handle(wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluate",
		RequestID:         2,
		ExpressionSetHash: initialized.ExpressionSetHash,
		RuleID:            "REGEX",
		FactsB64:          encodedFacts(t, descriptor, "REGEX", true),
	})
	if !evaluated.OK || evaluated.Value == nil || *evaluated.Value {
		t.Fatalf("evaluation response = %#v, want false", evaluated)
	}
}

func TestEvaluationDeadlineWinsOverLateSuccessfulResult(t *testing.T) {
	value, _, errorCode := evaluateProgram(deadlineSuccessProgram{}, nil, time.Millisecond)
	if value || errorCode != "EVALUATION_TIMEOUT" {
		t.Fatalf("evaluateProgram() = (%v, %q), want fail-open timeout", value, errorCode)
	}
}

func TestEvaluationUsesTypedCostCancellation(t *testing.T) {
	value, _, errorCode := evaluateProgram(costCancelledProgram{}, nil, time.Second)
	if value || errorCode != "EVALUATION_COST_LIMIT" {
		t.Fatalf("evaluateProgram() = (%v, %q), want typed cost-limit error", value, errorCode)
	}
}

func TestBuildUsesExactCelGoModule(t *testing.T) {
	if err := verifyCelGoBuildDependency(); err != nil {
		t.Fatalf("verifyCelGoBuildDependency() error = %v", err)
	}
}

func TestShutdownRejectsUnrelatedFields(t *testing.T) {
	server := &runtimeServer{}
	valid := server.handle(wireRequest{
		ProtocolVersion: protocolVersion,
		Type:            "shutdown",
		RequestID:       1,
	})
	if !valid.OK || valid.Type != "shutdown" {
		t.Fatalf("valid shutdown response = %#v", valid)
	}
	invalid := server.handle(wireRequest{
		ProtocolVersion: protocolVersion,
		Type:            "shutdown",
		RequestID:       2,
		FactsB64:        "unrelated",
	})
	if invalid.OK || invalid.ErrorCode != "INVALID_SHUTDOWN_REQUEST" {
		t.Fatalf("invalid shutdown response = %#v", invalid)
	}
	wrongProtocol := server.handle(wireRequest{Type: "shutdown", RequestID: 3})
	if wrongProtocol.OK || wrongProtocol.ErrorCode != "PROTOCOL_VERSION_MISMATCH" {
		t.Fatalf("wrong-protocol shutdown response = %#v", wrongProtocol)
	}
}

func FuzzLiteralRegexValidatorDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		`^\d{1,4}$`,
		`(?:a{1000}){5}`,
		`(?=lookahead)`,
		`[a-z]+(?:[.]sh)?$`,
		strings.Repeat("a", maxLiteralRegexChars+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, pattern string) {
		_ = validateLiteralRegex(pattern)
	})
}

func TestActivationRuleMismatchFailsOpen(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	if response := server.handle(initRequest(t, rules)); !response.OK {
		t.Fatalf("initialize response = %#v", response)
	}
	_, descriptor := testDescriptorSet(t)
	response := server.handle(wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluate",
		RequestID:         2,
		ExpressionSetHash: server.generation.expressionSetHash,
		RuleID:            "RULE",
		FactsB64:          encodedFacts(t, descriptor, "OTHER", true),
	})
	if response.OK || response.ErrorCode != "CANDIDATE_RULE_MISMATCH" {
		t.Fatalf("evaluation response = %#v", response)
	}
}

func TestActivationRequiresTopLevelMessages(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	_, descriptor := testDescriptorSet(t)
	for _, fieldName := range []protoreflect.Name{"skill", "candidate", "projection"} {
		t.Run(string(fieldName), func(t *testing.T) {
			facts := mutateEncodedFacts(t, descriptor, "RULE", func(message *dynamicpb.Message) {
				message.Clear(descriptor.Fields().ByName(fieldName))
			})
			response := server.handle(wireRequest{
				ProtocolVersion:   protocolVersion,
				Type:              "evaluate",
				RequestID:         2,
				ExpressionSetHash: initialized.ExpressionSetHash,
				RuleID:            "RULE",
				FactsB64:          facts,
			})
			if response.OK || response.ErrorCode != "ACTIVATION_INVALID" {
				t.Fatalf("evaluation response = %#v", response)
			}
		})
	}
}

func TestActivationRejectsUnknownProtobufFieldsRecursively(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	_, descriptor := testDescriptorSet(t)
	for _, test := range []struct {
		name   string
		mutate func(*dynamicpb.Message)
	}{
		{
			name: "top level",
			mutate: func(message *dynamicpb.Message) {
				message.SetUnknown([]byte{0xf8, 0x7f, 0x01})
			},
		},
		{
			name: "nested candidate",
			mutate: func(message *dynamicpb.Message) {
				candidateField := descriptor.Fields().ByName("candidate")
				candidate := message.Mutable(candidateField).Message()
				candidate.SetUnknown([]byte{0xf8, 0x7f, 0x01})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := server.handle(wireRequest{
				ProtocolVersion:   protocolVersion,
				Type:              "evaluate",
				RequestID:         2,
				ExpressionSetHash: initialized.ExpressionSetHash,
				RuleID:            "RULE",
				FactsB64:          mutateEncodedFacts(t, descriptor, "RULE", test.mutate),
			})
			if response.OK || response.ErrorCode != "ACTIVATION_UNKNOWN_FIELDS" {
				t.Fatalf("evaluation response = %#v", response)
			}
		})
	}
}

func TestActivationRejectsProtobufOverRecursionLimit(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	server := &runtimeServer{}
	initialized := server.handle(initRequest(t, rules))
	if !initialized.OK {
		t.Fatalf("initialize response = %#v", initialized)
	}
	_, descriptor := testDescriptorSet(t)
	raw, err := base64.StdEncoding.DecodeString(encodedFacts(t, descriptor, "RULE", true))
	if err != nil {
		t.Fatalf("base64.DecodeString() error = %v", err)
	}
	startGroup := binary.AppendUvarint(nil, uint64(127<<3|3))
	endGroup := binary.AppendUvarint(nil, uint64(127<<3|4))
	for range maxProtoRecursionDepth + 1 {
		raw = append(raw, startGroup...)
	}
	for range maxProtoRecursionDepth + 1 {
		raw = append(raw, endGroup...)
	}
	response := server.handle(wireRequest{
		ProtocolVersion:   protocolVersion,
		Type:              "evaluate",
		RequestID:         2,
		ExpressionSetHash: initialized.ExpressionSetHash,
		RuleID:            "RULE",
		FactsB64:          base64.StdEncoding.EncodeToString(raw),
	})
	if response.OK || response.ErrorCode != "ACTIVATION_UNKNOWN_FIELDS" {
		t.Fatalf("evaluation response = %#v", response)
	}
}

func TestExpressionSetHashMatchesPythonFraming(t *testing.T) {
	rules := []wireRule{{RuleID: "RULE", Expression: "f.projection.complete", FactSchema: supportedFactSchema}}
	digest, err := expressionSetHash(rules)
	if err != nil {
		t.Fatalf("expressionSetHash() error = %v", err)
	}
	const expected = "43dbe4fb1d3f1b76a9ce54c4a055f457a64105f1ca34ef07381b60fd34ccf253"
	if digest != expected {
		t.Fatalf("expressionSetHash() = %q, want %q", digest, expected)
	}
}

func TestHelpersRejectOversizedAndInvalidInputs(t *testing.T) {
	if _, err := decodeBoundedBase64(base64.StdEncoding.EncodeToString([]byte("too large")), 2); err == nil {
		t.Fatal("decodeBoundedBase64() accepted an oversized payload")
	}
	if isSHA256("ABC") {
		t.Fatal("isSHA256() accepted an invalid digest")
	}
}

func TestDecodeWireRequestRejectsAmbiguousJSON(t *testing.T) {
	valid := `{"protocol_version":2,"type":"shutdown","request_id":7}`
	request, err := decodeWireRequest([]byte(valid))
	if err != nil || request.Type != "shutdown" || request.RequestID != 7 {
		t.Fatalf("decodeWireRequest(valid) = %#v, %v", request, err)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate top-level field",
			raw:  `{"protocol_version":2,"type":"shutdown","type":"evaluate","request_id":7}`,
		},
		{
			name: "unknown top-level field",
			raw:  `{"protocol_version":2,"type":"shutdown","request_id":7,"extra":true}`,
		},
		{
			name: "duplicate nested rule field",
			raw:  `{"protocol_version":2,"type":"initialize","request_id":7,"rules":[{"rule_id":"A","rule_id":"B"}]}`,
		},
		{
			name: "unknown nested rule field",
			raw:  `{"protocol_version":2,"type":"initialize","request_id":7,"rules":[{"rule_id":"A","extra":true}]}`,
		},
		{
			name: "multiple values",
			raw:  valid + ` {}`,
		},
		{
			name: "non-object request",
			raw:  `[]`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeWireRequest([]byte(test.raw)); err == nil {
				t.Fatalf("decodeWireRequest(%s) unexpectedly succeeded", test.raw)
			}
		})
	}
}

func TestDecodeWireRequestRejectsExcessiveJSONNesting(t *testing.T) {
	nested := strings.Repeat("[", maxJSONNestingDepth+1) + "0" +
		strings.Repeat("]", maxJSONNestingDepth+1)
	raw := `{"protocol_version":2,"type":"shutdown","request_id":7,"rules":` + nested + `}`
	if _, err := decodeWireRequest([]byte(raw)); err == nil {
		t.Fatal("decodeWireRequest() accepted an excessively nested request")
	}
}

func TestDecodeWireRequestRejectsInvalidUTF8(t *testing.T) {
	raw := append([]byte(`{"protocol_version":2,"type":"shut`), 0xff)
	raw = append(raw, []byte(`down","request_id":7}`)...)
	if _, err := decodeWireRequest(raw); err == nil {
		t.Fatal("decodeWireRequest() accepted invalid UTF-8")
	}
}
