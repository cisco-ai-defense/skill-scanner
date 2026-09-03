# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ScanFacts(_message.Message):
    __slots__ = ("schema_version", "skill", "candidate", "projection")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    SKILL_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    PROJECTION_FIELD_NUMBER: _ClassVar[int]
    schema_version: str
    skill: SkillFacts
    candidate: CandidateFacts
    projection: ProjectionStatus
    def __init__(self, schema_version: _Optional[str] = ..., skill: _Optional[_Union[SkillFacts, _Mapping]] = ..., candidate: _Optional[_Union[CandidateFacts, _Mapping]] = ..., projection: _Optional[_Union[ProjectionStatus, _Mapping]] = ...) -> None: ...

class SkillFacts(_message.Message):
    __slots__ = ("name", "has_description", "declared_tools", "declares_network", "file_count", "total_bytes", "files", "commands", "urls", "flows", "reference_edges", "signals")
    NAME_FIELD_NUMBER: _ClassVar[int]
    HAS_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DECLARED_TOOLS_FIELD_NUMBER: _ClassVar[int]
    DECLARES_NETWORK_FIELD_NUMBER: _ClassVar[int]
    FILE_COUNT_FIELD_NUMBER: _ClassVar[int]
    TOTAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    FILES_FIELD_NUMBER: _ClassVar[int]
    COMMANDS_FIELD_NUMBER: _ClassVar[int]
    URLS_FIELD_NUMBER: _ClassVar[int]
    FLOWS_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_EDGES_FIELD_NUMBER: _ClassVar[int]
    SIGNALS_FIELD_NUMBER: _ClassVar[int]
    name: str
    has_description: bool
    declared_tools: _containers.RepeatedScalarFieldContainer[str]
    declares_network: bool
    file_count: int
    total_bytes: int
    files: _containers.RepeatedCompositeFieldContainer[FileFact]
    commands: _containers.RepeatedCompositeFieldContainer[CommandFact]
    urls: _containers.RepeatedCompositeFieldContainer[UrlFact]
    flows: _containers.RepeatedCompositeFieldContainer[FlowFact]
    reference_edges: _containers.RepeatedCompositeFieldContainer[ReferenceEdge]
    signals: _containers.RepeatedCompositeFieldContainer[SignalFact]
    def __init__(self, name: _Optional[str] = ..., has_description: bool = ..., declared_tools: _Optional[_Iterable[str]] = ..., declares_network: bool = ..., file_count: _Optional[int] = ..., total_bytes: _Optional[int] = ..., files: _Optional[_Iterable[_Union[FileFact, _Mapping]]] = ..., commands: _Optional[_Iterable[_Union[CommandFact, _Mapping]]] = ..., urls: _Optional[_Iterable[_Union[UrlFact, _Mapping]]] = ..., flows: _Optional[_Iterable[_Union[FlowFact, _Mapping]]] = ..., reference_edges: _Optional[_Iterable[_Union[ReferenceEdge, _Mapping]]] = ..., signals: _Optional[_Iterable[_Union[SignalFact, _Mapping]]] = ...) -> None: ...

class CandidateFacts(_message.Message):
    __slots__ = ("rule_id", "analyzer", "category", "severity", "file_path", "line", "evidence_kind", "context_kind", "file", "command", "url", "flow", "cooccurring_rule_ids", "evidence_value_class", "evidence_count")
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    ANALYZER_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_KIND_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_KIND_FIELD_NUMBER: _ClassVar[int]
    FILE_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    FLOW_FIELD_NUMBER: _ClassVar[int]
    COOCCURRING_RULE_IDS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_VALUE_CLASS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_COUNT_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    analyzer: str
    category: str
    severity: str
    file_path: str
    line: int
    evidence_kind: str
    context_kind: str
    file: FileFact
    command: CommandFact
    url: UrlFact
    flow: FlowFact
    cooccurring_rule_ids: _containers.RepeatedScalarFieldContainer[str]
    evidence_value_class: str
    evidence_count: int
    def __init__(self, rule_id: _Optional[str] = ..., analyzer: _Optional[str] = ..., category: _Optional[str] = ..., severity: _Optional[str] = ..., file_path: _Optional[str] = ..., line: _Optional[int] = ..., evidence_kind: _Optional[str] = ..., context_kind: _Optional[str] = ..., file: _Optional[_Union[FileFact, _Mapping]] = ..., command: _Optional[_Union[CommandFact, _Mapping]] = ..., url: _Optional[_Union[UrlFact, _Mapping]] = ..., flow: _Optional[_Union[FlowFact, _Mapping]] = ..., cooccurring_rule_ids: _Optional[_Iterable[str]] = ..., evidence_value_class: _Optional[str] = ..., evidence_count: _Optional[int] = ...) -> None: ...

class FileFact(_message.Message):
    __slots__ = ("path", "extension", "kind", "role", "size_bytes", "hidden", "executable", "referenced", "analyzable", "magic_mismatch", "archive_depth")
    PATH_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_FIELD_NUMBER: _ClassVar[int]
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    REFERENCED_FIELD_NUMBER: _ClassVar[int]
    ANALYZABLE_FIELD_NUMBER: _ClassVar[int]
    MAGIC_MISMATCH_FIELD_NUMBER: _ClassVar[int]
    ARCHIVE_DEPTH_FIELD_NUMBER: _ClassVar[int]
    path: str
    extension: str
    kind: str
    role: str
    size_bytes: int
    hidden: bool
    executable: bool
    referenced: bool
    analyzable: bool
    magic_mismatch: bool
    archive_depth: int
    def __init__(self, path: _Optional[str] = ..., extension: _Optional[str] = ..., kind: _Optional[str] = ..., role: _Optional[str] = ..., size_bytes: _Optional[int] = ..., hidden: bool = ..., executable: bool = ..., referenced: bool = ..., analyzable: bool = ..., magic_mismatch: bool = ..., archive_depth: _Optional[int] = ...) -> None: ...

class CommandFact(_message.Message):
    __slots__ = ("executable", "argument_classes", "downloads", "executes", "destructive", "privilege_change", "source_class", "sink_class", "file_path")
    EXECUTABLE_FIELD_NUMBER: _ClassVar[int]
    ARGUMENT_CLASSES_FIELD_NUMBER: _ClassVar[int]
    DOWNLOADS_FIELD_NUMBER: _ClassVar[int]
    EXECUTES_FIELD_NUMBER: _ClassVar[int]
    DESTRUCTIVE_FIELD_NUMBER: _ClassVar[int]
    PRIVILEGE_CHANGE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    SINK_CLASS_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    executable: str
    argument_classes: _containers.RepeatedScalarFieldContainer[str]
    downloads: bool
    executes: bool
    destructive: bool
    privilege_change: bool
    source_class: str
    sink_class: str
    file_path: str
    def __init__(self, executable: _Optional[str] = ..., argument_classes: _Optional[_Iterable[str]] = ..., downloads: bool = ..., executes: bool = ..., destructive: bool = ..., privilege_change: bool = ..., source_class: _Optional[str] = ..., sink_class: _Optional[str] = ..., file_path: _Optional[str] = ...) -> None: ...

class UrlFact(_message.Message):
    __slots__ = ("scheme", "host", "domain_class", "trusted_installer", "method", "direction", "file_path")
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_CLASS_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_INSTALLER_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    scheme: str
    host: str
    domain_class: str
    trusted_installer: bool
    method: str
    direction: str
    file_path: str
    def __init__(self, scheme: _Optional[str] = ..., host: _Optional[str] = ..., domain_class: _Optional[str] = ..., trusted_installer: bool = ..., method: _Optional[str] = ..., direction: _Optional[str] = ..., file_path: _Optional[str] = ...) -> None: ...

class FlowFact(_message.Message):
    __slots__ = ("source_class", "sink_class", "transforms", "cross_file", "source_path", "sink_path")
    SOURCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    SINK_CLASS_FIELD_NUMBER: _ClassVar[int]
    TRANSFORMS_FIELD_NUMBER: _ClassVar[int]
    CROSS_FILE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PATH_FIELD_NUMBER: _ClassVar[int]
    SINK_PATH_FIELD_NUMBER: _ClassVar[int]
    source_class: str
    sink_class: str
    transforms: _containers.RepeatedScalarFieldContainer[str]
    cross_file: bool
    source_path: str
    sink_path: str
    def __init__(self, source_class: _Optional[str] = ..., sink_class: _Optional[str] = ..., transforms: _Optional[_Iterable[str]] = ..., cross_file: bool = ..., source_path: _Optional[str] = ..., sink_path: _Optional[str] = ...) -> None: ...

class ReferenceEdge(_message.Message):
    __slots__ = ("source_path", "target_path", "kind")
    SOURCE_PATH_FIELD_NUMBER: _ClassVar[int]
    TARGET_PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    source_path: str
    target_path: str
    kind: str
    def __init__(self, source_path: _Optional[str] = ..., target_path: _Optional[str] = ..., kind: _Optional[str] = ...) -> None: ...

class SignalFact(_message.Message):
    __slots__ = ("rule_id", "kind", "file_path", "value_class")
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    VALUE_CLASS_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    kind: str
    file_path: str
    value_class: str
    def __init__(self, rule_id: _Optional[str] = ..., kind: _Optional[str] = ..., file_path: _Optional[str] = ..., value_class: _Optional[str] = ...) -> None: ...

class ProjectionStatus(_message.Message):
    __slots__ = ("complete", "error_codes", "serialized_bytes", "truncated")
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODES_FIELD_NUMBER: _ClassVar[int]
    SERIALIZED_BYTES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    complete: bool
    error_codes: _containers.RepeatedScalarFieldContainer[str]
    serialized_bytes: int
    truncated: bool
    def __init__(self, complete: bool = ..., error_codes: _Optional[_Iterable[str]] = ..., serialized_bytes: _Optional[int] = ..., truncated: bool = ...) -> None: ...
