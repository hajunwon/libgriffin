#pragma once
#include <pefix/pe.h>
#include <pefix/x86_64/ir.h>
#include <cstdint>
#include <vector>

namespace griffin {

struct ResolvedJmp {
    uint32_t jmpRVA;
    uint32_t targetRVA;
    uint8_t jmpLen;
};

struct JmpResStats {
    uint32_t totalIndirect;
    uint32_t resolved;
    uint32_t patched;
};

std::vector<ResolvedJmp> resolveIndirectJumps(
    const pefix::PEFile& pe, uint64_t imageBase,
    const std::vector<uint32_t>& funcRVAs);

JmpResStats patchIndirectJumps(pefix::PEFile& pe, uint64_t imageBase,
    const std::vector<ResolvedJmp>& resolved);

struct ResolvedIndirectCall {
    uint32_t instrRVA;
    uint32_t pointerRVA;
    uint32_t targetRVA;
    bool isCall;
};

struct IndirectCallStats {
    uint32_t totalScanned;
    uint32_t resolved;
    uint32_t patched;
    uint32_t skippedIAT;
    uint32_t skippedExternal;
};

std::vector<ResolvedIndirectCall> resolveIndirectCalls(
    const pefix::PEFile& pe, uint64_t imageBase);

IndirectCallStats patchIndirectCalls(pefix::PEFile& pe, uint64_t imageBase,
    const std::vector<ResolvedIndirectCall>& resolved);

} // namespace griffin
