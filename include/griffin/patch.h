#pragma once
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <cstdint>
#include <vector>
#include <string>

namespace griffin {

struct PatchStats {
    uint32_t nopsWritten;
    uint32_t imulFolded;
    uint32_t cmovResolved;
    uint32_t totalPatched;
    uint32_t bytesPatched;
};

PatchStats applyDeobfPatches(pefix::PEFile& pe, uint64_t imageBase, const pefix::Func& func);

struct NullsubPatch {
    uint32_t fileOffset;
    uint32_t rva;
};

// Patch C3 90 E9 00 00 00 00 48 B8 nullsub patterns and standalone C3 in obfuscated sections.
// obfuscatedSections: list of section name prefixes to treat as obfuscated (e.g. ".grfn", ".riot")
std::vector<NullsubPatch> patchNullsubs(pefix::PEFile& pe,
    const std::vector<std::string>& obfuscatedSections = {".grfn", ".riot"});

struct InlineInt3Stats {
    uint32_t bytesNoped;
};

// NOP inline INT3 constant data embedded between code.
// Griffin VEH uses CC runs as inline data; NOP them so disassemblers can parse through.
// filter: section name predicate (nullptr = all executable sections)
using SectionFilter = bool(*)(const char* sectionName);
InlineInt3Stats nopInlineInt3(pefix::PEFile& pe, SectionFilter filter = nullptr);

} // namespace griffin
