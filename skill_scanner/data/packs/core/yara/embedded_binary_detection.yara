/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Detects embedded executable content in binary files within skill packages.
 * Catches ELF binaries, PE executables, Mach-O binaries, and shebang scripts
 * that may indicate supply chain compromise or hidden payloads.
 */

rule embedded_elf_binary
{
    meta:
        author = "Cisco Security"
        description = "Detects ELF executable headers embedded in skill package files"
        classification = "SUPPLY CHAIN ATTACK"
        threat_type = "supply_chain_attack"
        category = "supply_chain_attack"
        severity = "HIGH"

    strings:
        $elf_magic = { 7F 45 4C 46 }  // ELF magic bytes

    condition:
        $elf_magic
}

rule embedded_pe_executable
{
    meta:
        author = "Cisco Security"
        description = "Detects PE (Windows) executable headers embedded in skill package files"
        classification = "SUPPLY CHAIN ATTACK"
        threat_type = "supply_chain_attack"
        category = "supply_chain_attack"
        severity = "HIGH"

    strings:
        $pe_sig = "PE\x00\x00"

    condition:
        // Use a direct header check instead of a two-byte pattern, which has
        // no useful YARA atom and would otherwise be verified too broadly.
        uint16(0) == 0x5A4D and $pe_sig
}

rule embedded_macho_binary
{
    meta:
        author = "Cisco Security"
        description = "Detects Mach-O (macOS) executable headers embedded in skill package files"
        classification = "SUPPLY CHAIN ATTACK"
        threat_type = "supply_chain_attack"
        category = "supply_chain_attack"
        severity = "HIGH"

    strings:
        $macho_32 = { CE FA ED FE }  // 32-bit Mach-O
        $macho_64 = { CF FA ED FE }  // 64-bit Mach-O
        $macho_32_be = { FE ED FA CE }  // 32-bit Mach-O, big-endian
        $macho_64_be = { FE ED FA CF }  // 64-bit Mach-O, big-endian
        $macho_fat = { CA FE BA BE }  // Universal/fat binary
        $macho_fat_swapped = { BE BA FE CA }  // Universal/fat, swapped endian
        $macho_fat64 = { CA FE BA BF }  // 64-bit universal/fat binary
        $macho_fat64_swapped = { BF BA FE CA }  // 64-bit universal/fat, swapped endian

    condition:
        ($macho_32 at 0) or
        ($macho_64 at 0) or
        ($macho_32_be at 0) or
        ($macho_64_be at 0) or
        // Java class files share CAFEBABE. Their minor/major version fields
        // occupy bytes 4-7; valid class major versions start at 45.
        ($macho_fat at 0 and not (uint16be(4) == 0 and uint16be(6) >= 45 and uint16be(6) <= 100)) or
        ($macho_fat_swapped at 0) or
        ($macho_fat64 at 0) or
        ($macho_fat64_swapped at 0)
}

rule embedded_shebang_in_binary
{
    meta:
        author = "Cisco Security"
        description = "Detects shebang script headers embedded within binary content"
        classification = "SUPPLY CHAIN ATTACK"
        threat_type = "supply_chain_attack"
        category = "supply_chain_attack"
        severity = "MEDIUM"

    strings:
        $shebang_bash = "#!/bin/bash"
        $shebang_sh = "#!/bin/sh"
        $shebang_python = "#!/usr/bin/env python"
        $shebang_python3 = "#!/usr/bin/python"
        $shebang_perl = "#!/usr/bin/perl"
        $shebang_ruby = "#!/usr/bin/ruby"
        $shebang_node = "#!/usr/bin/env node"

    condition:
        // Only flag when shebang is deeply embedded (offset > 64), not just after
        // a small header. The application layer also restricts this rule to binary
        // files only; text files with shebangs in code blocks are not flagged.
        for any of ($shebang_*) : (@ > 64)
}
