#pragma once
#include <pefix/pe.h>
#include <pefix/x86_64/trace.h>
#include <cstdint>
#include <vector>
#include <string>

namespace griffin {

enum XrefLayer : uint8_t {
    XrefLayerGrfn1  = 1,  // root: .grfn1 (obfuscated code as entry)
    XrefLayerExport = 2,  // root: PE exports (external callers)
    XrefLayerFnPtr  = 3,  // root: function pointers stored in .data/.rdata
    XrefLayerFbr    = 5,  // root: FBR-discovered functions absent from other roots
};

struct ResolvedXref {
    uint32_t instrRVA;
    uint32_t targetRVA;
    uint64_t targetVA;
    uint8_t layer = XrefLayerGrfn1;
};

struct XrefResult {
    std::vector<ResolvedXref> xrefs;
    uint32_t functionsMatched = 0;
    uint32_t uniqueTargets = 0;
    uint32_t layerTargets[8] = {};
};

struct XrefTraceResult {
    std::vector<ResolvedXref> xrefs;
    uint32_t functionsTraced = 0;
    uint32_t totalSteps = 0;
    uint32_t hadCalls = 0;
};

struct DispatchEntry {
    uint32_t funcRVA;
    int64_t key;
    uint8_t keyReg;
    uint32_t firstImulRVA = 0;
    std::vector<uint32_t> imulConsts;
};

XrefResult resolveGriffinXrefs(const pefix::PEFile& pe, uint64_t imageBase,
                                uint32_t maxDepth = 3);

// Add reachability from PE-export entry points. New targets get layer=XrefLayerExport;
// existing layer-1 targets are not duplicated.
void extendWithExportRoots(XrefResult& result, const pefix::PEFile& pe,
                           uint64_t imageBase, uint32_t maxDepth = 3);

// Add reachability from function pointers stored in .data/.rdata. Each 8-byte
// aligned slot whose value falls in .text and resolves to a known function in
// the graph context becomes a root; new targets get layer=XrefLayerFnPtr. Catches
// descriptor wrappers and other handlers that no LEA / E8 directly references.
void extendWithFnPtrRoots(XrefResult& result, const pefix::PEFile& pe,
                          uint64_t imageBase, uint32_t maxDepth = 3);

// For protobuf-style "pkg.Msg.field" strings: if the container is reachable,
// every position after a '.' is also a valid target (the runtime indexes into
// the longer string by offset rather than holding a pointer to each suffix).
void expandSubstringTargets(XrefResult& result, const pefix::PEFile& pe,
                            uint64_t imageBase);

// Append-only enrichment. Pulls function boundaries from pefix::fbr that are
// NOT already used as roots by the L1/L2/L3 paths, and registers the .rdata
// targets reachable from them as XrefLayerFbr entries. Existing entries are
// not modified. Safe to call without other extensions.
//
// strictOnly: when true, only "strong" FBR boundaries are used — those
// confirmed by pdata / export / RTTI / EH handler tables, or seen by >= 2
// independent sources. False (default) keeps the wider net.
void extendWithFbrRoots(XrefResult& result, const pefix::PEFile& pe,
                        uint64_t imageBase, uint32_t maxDepth = 3,
                        bool strictOnly = false);

XrefTraceResult traceImageTableXrefs(const pefix::PEFile& pe, uint64_t imageBase,
                                      uint32_t maxStepsPerFunc = 500000);

XrefTraceResult traceDispatchKeys(const pefix::PEFile& pe, uint64_t imageBase,
                                   const std::vector<DispatchEntry>& entries,
                                   uint32_t maxStepsPerFunc = 50000);

struct DebugTraceResult {
    std::vector<pefix::TraceStep> steps;
    std::vector<pefix::TraceCall> calls;
    uint64_t stepsExecuted;
    std::string stopReason;
};

DebugTraceResult debugTraceSingle(const pefix::PEFile& pe, uint64_t imageBase,
                                   const DispatchEntry& entry,
                                   uint32_t maxSteps = 500, uint32_t logLimit = 500);

} // namespace griffin
