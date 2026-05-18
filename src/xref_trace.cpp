#include <griffin/xref_trace.h>
#include <pefix/x86_64/disasm.h>
#include <pefix/xrefs.h>
#include <pefix/exports.h>
#include <pefix/fbr.h>
#include <cstring>
#include <algorithm>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

namespace griffin {

using pefix::PEFile;
using pefix::Tracer;
using pefix::Reg;

// Per-PE state reused across the layered queries.
struct XrefGraphCtx {
    uint32_t rdataStart, rdataEnd;
    uint32_t textStart, textEnd;
    uint32_t grfnStart, grfnEnd, grfnRawSz, grfnRaw;
    std::vector<uint32_t> funcStarts;
    std::unordered_map<uint32_t, std::set<uint32_t>> reachable;
    std::vector<std::pair<uint32_t, uint32_t>> grfnCalls;
    std::vector<pefix::RipRelativeRef> allRefs;

    uint32_t findFunc(uint32_t rva) const {
        auto it = std::upper_bound(funcStarts.begin(), funcStarts.end(), rva);
        if (it != funcStarts.begin()) { --it; return *it; }
        return rva;
    }
};

static uint32_t findSection(const PEFile& pe, const char* target,
                             uint32_t& outStart, uint32_t& outEnd, uint32_t& outRaw) {
    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        if (strcmp(name, target) == 0) {
            outStart = pe.sections[i].VirtualAddress;
            outEnd = outStart + pe.sections[i].Misc.VirtualSize;
            outRaw = pe.sections[i].PointerToRawData;
            return pe.sections[i].SizeOfRawData;
        }
    }
    outStart = outEnd = outRaw = 0;
    return 0;
}


// Returns ctx with rdataStart=0 if any required section is missing.
static XrefGraphCtx buildXrefGraphCtx(const PEFile& pe, uint64_t imageBase, uint32_t maxDepth) {
    XrefGraphCtx ctx = {};

    uint32_t rdataRaw;
    findSection(pe, ".rdata", ctx.rdataStart, ctx.rdataEnd, rdataRaw);
    ctx.grfnRawSz = findSection(pe, ".grfn1", ctx.grfnStart, ctx.grfnEnd, ctx.grfnRaw);
    if (!ctx.rdataStart || !ctx.grfnStart) return ctx;

    uint32_t textRaw = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        if (pe.sections[i].Characteristics & 0x20000000) {
            char nm[9] = {}; memcpy(nm, pe.sections[i].Name, 8);
            if (strcmp(nm, ".grfn1") != 0 && strcmp(nm, ".riot1") != 0) {
                ctx.textStart = pe.sections[i].VirtualAddress;
                ctx.textEnd = ctx.textStart + pe.sections[i].Misc.VirtualSize;
                textRaw = pe.sections[i].PointerToRawData;
                break;
            }
        }
    }
    if (!ctx.textStart) { ctx.rdataStart = 0; return ctx; }
    uint32_t textRawSz = ctx.textEnd - ctx.textStart;

    uint32_t pdataOff = 0, pdataSz = 0, pdataRaw = 0;
    findSection(pe, ".pdata", pdataOff, pdataSz, pdataRaw);
    if (pdataRaw) {
        uint32_t pdataRawSz = pdataSz - pdataOff;
        uint32_t count = pdataRawSz / 12;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t begin = *(uint32_t*)(pe.data.data() + pdataRaw + i * 12);
            if (begin >= ctx.textStart && begin < ctx.textEnd)
                ctx.funcStarts.push_back(begin);
        }
    }
    std::sort(ctx.funcStarts.begin(), ctx.funcStarts.end());
    ctx.funcStarts.erase(std::unique(ctx.funcStarts.begin(), ctx.funcStarts.end()),
                         ctx.funcStarts.end());

    ctx.allRefs = pefix::scanRipRelativeRefs(pe, imageBase);
    std::unordered_map<uint32_t, std::set<uint32_t>> funcRdata;
    for (auto& ref : ctx.allRefs) {
        if (ref.instrRVA < ctx.textStart || ref.instrRVA >= ctx.textEnd) continue;
        if (ref.targetRVA < ctx.rdataStart || ref.targetRVA >= ctx.rdataEnd) continue;
        funcRdata[ctx.findFunc(ref.instrRVA)].insert(ref.targetRVA);
    }

    std::unordered_map<uint32_t, std::set<uint32_t>> callGraph;
    for (uint32_t pos = 0; pos + 5 <= textRawSz; pos++) {
        uint8_t b = pe.data[textRaw + pos];
        if (b != 0xE8 && b != 0xE9) continue;
        int32_t disp = *(int32_t*)(pe.data.data() + textRaw + pos + 1);
        uint32_t instrRVA = ctx.textStart + pos;
        uint32_t target = instrRVA + 5 + disp;
        if (target >= ctx.textStart && target < ctx.textEnd)
            callGraph[ctx.findFunc(instrRVA)].insert(ctx.findFunc(target));
    }

    for (auto& [tfunc, rdataSet] : funcRdata) {
        std::vector<uint32_t> snapshot(rdataSet.begin(), rdataSet.end());
        for (uint32_t tgt : snapshot) {
            uint32_t tgtOff = pe.rvaToOffset(tgt);
            if (!tgtOff) continue;
            for (uint32_t slot = 0; slot < 64 && tgtOff + slot * 8 + 8 <= pe.data.size(); slot++) {
                uint64_t val = *(uint64_t*)(pe.data.data() + tgtOff + slot * 8);
                if (val < imageBase) { if (slot > 0) break; continue; }
                uint32_t fRVA = (uint32_t)(val - imageBase);
                if (fRVA < ctx.textStart || fRVA >= ctx.textEnd) {
                    if (slot > 0) break;
                    continue;
                }
                callGraph[tfunc].insert(ctx.findFunc(fRVA));
            }
        }
    }

    ctx.reachable = funcRdata;
    for (uint32_t depth = 1; depth <= maxDepth; depth++) {
        uint32_t added = 0;
        for (auto& [caller, callees] : callGraph) {
            for (uint32_t callee : callees) {
                auto it = ctx.reachable.find(callee);
                if (it == ctx.reachable.end()) continue;
                auto& dst = ctx.reachable[caller];
                for (uint32_t rva : it->second)
                    if (dst.insert(rva).second) added++;
            }
        }
        if (added == 0) break;
    }

    for (uint32_t pos = 0; pos + 5 <= ctx.grfnRawSz; pos++) {
        uint8_t b = pe.data[ctx.grfnRaw + pos];
        if (b != 0xE8 && b != 0xE9) continue;
        int32_t disp = *(int32_t*)(pe.data.data() + ctx.grfnRaw + pos + 1);
        uint32_t instrRVA = ctx.grfnStart + pos;
        uint32_t target = instrRVA + 5 + disp;
        if (target >= ctx.textStart && target < ctx.textEnd)
            ctx.grfnCalls.emplace_back(instrRVA, target);
    }
    return ctx;
}

XrefResult resolveGriffinXrefs(const PEFile& pe, uint64_t imageBase, uint32_t maxDepth) {
    XrefResult result = {};
    XrefGraphCtx ctx = buildXrefGraphCtx(pe, imageBase, maxDepth);
    if (!ctx.rdataStart) return result;

    std::set<uint32_t> allTargets;
    std::set<std::pair<uint32_t,uint32_t>> pairs;

    for (auto& gc : ctx.grfnCalls) {
        uint32_t func = ctx.findFunc(gc.second);
        auto it = ctx.reachable.find(func);
        if (it == ctx.reachable.end()) it = ctx.reachable.find(gc.second);
        if (it == ctx.reachable.end()) continue;
        for (uint32_t rva : it->second) {
            pairs.insert({gc.first, rva});
            allTargets.insert(rva);
        }
    }

    // .grfn1 LEA into .rdata. If the target is a vtable/ops table, treat each
    // slot's function as reachable from this .grfn1 site.
    for (auto& ref : ctx.allRefs) {
        if (ref.instrRVA < ctx.grfnStart || ref.instrRVA >= ctx.grfnEnd) continue;
        if (ref.targetRVA < ctx.rdataStart || ref.targetRVA >= ctx.rdataEnd) continue;
        pairs.insert({ref.instrRVA, ref.targetRVA});
        allTargets.insert(ref.targetRVA);

        uint32_t tgtOff = pe.rvaToOffset(ref.targetRVA);
        if (!tgtOff) continue;
        for (uint32_t slot = 0; slot < 64 && tgtOff + slot * 8 + 8 <= pe.data.size(); slot++) {
            uint64_t val = *(uint64_t*)(pe.data.data() + tgtOff + slot * 8);
            if (val < imageBase) { if (slot > 0) break; continue; }
            uint32_t fRVA = (uint32_t)(val - imageBase);
            if (fRVA < ctx.textStart || fRVA >= ctx.textEnd) { if (slot > 0) break; continue; }
            uint32_t func = ctx.findFunc(fRVA);
            auto it = ctx.reachable.find(func);
            if (it == ctx.reachable.end()) it = ctx.reachable.find(fRVA);
            if (it == ctx.reachable.end()) continue;
            for (uint32_t rva : it->second) {
                pairs.insert({ref.instrRVA, rva});
                allTargets.insert(rva);
            }
        }
    }

    for (auto& [instr, target] : pairs)
        result.xrefs.push_back({instr, target, imageBase + target, XrefLayerGrfn1});

    result.functionsMatched = (uint32_t)ctx.grfnCalls.size();
    result.uniqueTargets = (uint32_t)allTargets.size();
    result.layerTargets[XrefLayerGrfn1] = (uint32_t)allTargets.size();
    return result;
}


void extendWithExportRoots(XrefResult& result, const PEFile& pe, uint64_t imageBase, uint32_t maxDepth) {
    XrefGraphCtx ctx = buildXrefGraphCtx(pe, imageBase, maxDepth);
    if (!ctx.rdataStart) return;

    auto exports = pefix::readExports(pe);
    if (exports.empty()) return;

    std::set<uint32_t> known;
    for (auto& xr : result.xrefs) known.insert(xr.targetRVA);

    std::set<std::pair<uint32_t, uint32_t>> newPairs;
    std::set<uint32_t> newTargets;
    for (auto& ex : exports) {
        if (ex.isForwarder) continue;
        if (ex.rva < ctx.textStart || ex.rva >= ctx.textEnd) continue;
        uint32_t func = ctx.findFunc(ex.rva);
        auto it = ctx.reachable.find(func);
        if (it == ctx.reachable.end()) it = ctx.reachable.find(ex.rva);
        if (it == ctx.reachable.end()) continue;
        for (uint32_t rva : it->second) {
            if (known.count(rva)) continue;
            newTargets.insert(rva);
            newPairs.insert({ex.rva, rva});
        }
    }

    for (auto& [src, tgt] : newPairs)
        result.xrefs.push_back({src, tgt, imageBase + tgt, XrefLayerExport});

    result.uniqueTargets += (uint32_t)newTargets.size();
    result.layerTargets[XrefLayerExport] = (uint32_t)newTargets.size();
}


void extendWithFnPtrRoots(XrefResult& result, const PEFile& pe, uint64_t imageBase, uint32_t maxDepth) {
    XrefGraphCtx ctx = buildXrefGraphCtx(pe, imageBase, maxDepth);
    if (!ctx.rdataStart) return;

    std::set<uint32_t> known;
    for (auto& xr : result.xrefs) known.insert(xr.targetRVA);

    std::set<std::pair<uint32_t, uint32_t>> newPairs;
    std::set<uint32_t> newTargets;
    std::unordered_set<uint32_t> seenRoots;

    for (WORD si = 0; si < pe.numSections; si++) {
        if (pe.sections[si].Characteristics & 0x20000000) continue;
        char nm[9] = {}; memcpy(nm, pe.sections[si].Name, 8);
        if (strcmp(nm, ".rdata") != 0 && strcmp(nm, ".data") != 0) continue;

        uint32_t secStart = pe.sections[si].VirtualAddress;
        uint32_t secSize = pe.sections[si].Misc.VirtualSize;
        uint32_t raw = pe.sections[si].PointerToRawData;
        if (raw + secSize > pe.data.size()) continue;

        for (uint32_t off = 0; off + 8 <= secSize; off += 8) {
            uint64_t val = *(uint64_t*)(pe.data.data() + raw + off);
            if (val < imageBase) continue;
            uint32_t fnRVA = (uint32_t)(val - imageBase);
            if (fnRVA < ctx.textStart || fnRVA >= ctx.textEnd) continue;

            // Slot must point exactly to a known function start (pdata-derived),
            // otherwise it's a code address but not necessarily a callable target.
            uint32_t fn = ctx.findFunc(fnRVA);
            if (fn != fnRVA) continue;
            if (!seenRoots.insert(fnRVA).second) continue;

            auto it = ctx.reachable.find(fn);
            if (it == ctx.reachable.end()) continue;

            uint32_t slotRVA = secStart + off;
            for (uint32_t rva : it->second) {
                if (known.count(rva)) continue;
                newTargets.insert(rva);
                newPairs.insert({slotRVA, rva});
            }
        }
    }

    for (auto& [src, tgt] : newPairs)
        result.xrefs.push_back({src, tgt, imageBase + tgt, XrefLayerFnPtr});

    result.uniqueTargets += (uint32_t)newTargets.size();
    result.layerTargets[XrefLayerFnPtr] = (uint32_t)newTargets.size();
}


void extendWithFbrRoots(XrefResult& result, const PEFile& pe, uint64_t imageBase,
                        uint32_t maxDepth, bool strictOnly) {
    XrefGraphCtx ctx = buildXrefGraphCtx(pe, imageBase, maxDepth);
    if (!ctx.rdataStart) return;

    auto fbr = pefix::discoverFunctionBoundaries(pe, imageBase);
    if (fbr.functions.empty()) return;

    auto isStrong = [](const pefix::FunctionBoundary& f) {
        uint16_t strongMask = pefix::SRC_PDATA | pefix::SRC_EXPORT |
                              pefix::SRC_RTTI_VFUNC | pefix::SRC_EH_HANDLER;
        return (f.sources & strongMask) != 0 || f.sourceCount >= 2;
    };

    // Functions already covered by L1/L2/L3 (mapped via the existing root
    // paths). instrRVA in result.xrefs is a *call site*, not a function start  - 
    // map it back to the owning function via ctx.findFunc so we can compare
    // against FBR's startRVA list. Anything already represented here is
    // skipped so FBR only contributes net-new roots.
    std::unordered_set<uint32_t> knownRootFuncs;
    knownRootFuncs.reserve(result.xrefs.size() / 4);
    for (auto& xr : result.xrefs)
        knownRootFuncs.insert(ctx.findFunc(xr.instrRVA));

    // Existing targets  - don't re-register the same target under FBR layer if
    // some earlier root already reached it.
    std::unordered_set<uint32_t> knownTargets;
    knownTargets.reserve(result.uniqueTargets);
    for (auto& xr : result.xrefs)
        knownTargets.insert(xr.targetRVA);

    std::set<std::pair<uint32_t, uint32_t>> newPairs;
    std::set<uint32_t> newTargets;

    for (auto& fb : fbr.functions) {
        if (fb.startRVA < ctx.textStart || fb.startRVA >= ctx.textEnd) continue;
        if (strictOnly && !isStrong(fb)) continue;
        // Skip if this RVA is the canonical start of a function already used
        // as a root by L1/L2/L3.
        if (knownRootFuncs.count(fb.startRVA)) continue;

        // Only consider FBR entries that the graph context recognises as a
        // function start. ctx.reachable was populated from RIP-relative refs
        // grouped by ctx.findFunc(...), so without an entry there's nothing
        // to add.
        auto it = ctx.reachable.find(fb.startRVA);
        if (it == ctx.reachable.end()) continue;

        for (uint32_t rva : it->second) {
            if (knownTargets.count(rva)) continue;
            newTargets.insert(rva);
            newPairs.insert({fb.startRVA, rva});
        }
    }

    // .grfn1 FBR functions: ctx.reachable doesn't index them (it's built from
    // .text-only func boundaries), so use direct LEA refs inside each FBR
    // function's [startRVA, endRVA) range. No transitive propagation  - 
    // direct .rdata targets only, which keeps the contribution local and
    // avoids the BFS-depth fragmentation that broke the earlier integration.
    for (auto& fb : fbr.functions) {
        if (fb.startRVA < ctx.grfnStart || fb.startRVA >= ctx.grfnEnd) continue;
        if (strictOnly && !isStrong(fb)) continue;
        if (fb.endRVA <= fb.startRVA) continue;

        for (auto& ref : ctx.allRefs) {
            if (ref.instrRVA < fb.startRVA || ref.instrRVA >= fb.endRVA) continue;
            if (ref.targetRVA < ctx.rdataStart || ref.targetRVA >= ctx.rdataEnd) continue;
            if (knownTargets.count(ref.targetRVA)) continue;
            newTargets.insert(ref.targetRVA);
            newPairs.insert({fb.startRVA, ref.targetRVA});
        }
    }

    for (auto& [src, tgt] : newPairs)
        result.xrefs.push_back({src, tgt, imageBase + tgt, (uint8_t)XrefLayerFbr});

    result.uniqueTargets += (uint32_t)newTargets.size();
    result.layerTargets[XrefLayerFbr] = (uint32_t)newTargets.size();
}


void expandSubstringTargets(XrefResult& result, const PEFile& pe, uint64_t imageBase) {
    uint32_t rdataStart, rdataEnd, rdataRaw;
    findSection(pe, ".rdata", rdataStart, rdataEnd, rdataRaw);
    if (!rdataStart) return;

    struct CallerInfo { uint32_t caller; uint8_t layer; };
    std::unordered_map<uint32_t, std::vector<CallerInfo>> targetToCallers;
    for (auto& xr : result.xrefs)
        targetToCallers[xr.targetRVA].push_back({xr.instrRVA, xr.layer});

    std::set<std::tuple<uint32_t, uint32_t, uint8_t>> newTriples;
    std::set<uint32_t> newTargets;

    for (auto& [containerRVA, callers] : targetToCallers) {
        if (containerRVA < rdataStart || containerRVA >= rdataEnd) continue;
        uint32_t off = pe.rvaToOffset(containerRVA);
        if (!off || off >= pe.data.size()) continue;

        uint32_t maxLen = std::min((uint32_t)256, (uint32_t)(pe.data.size() - off));
        for (uint32_t i = 0; i < maxLen; i++) {
            uint8_t b = pe.data[off + i];
            if (b == 0) break;
            if (b != '.') continue;
            uint32_t subRVA = containerRVA + i + 1;
            if (subRVA >= rdataEnd) break;
            if (targetToCallers.count(subRVA)) continue;
            newTargets.insert(subRVA);
            for (auto& c : callers)
                newTriples.insert({c.caller, subRVA, c.layer});
        }
    }

    for (auto& [caller, sub, layer] : newTriples)
        result.xrefs.push_back({caller, sub, imageBase + sub, layer});
    result.uniqueTargets += (uint32_t)newTargets.size();
}


XrefTraceResult traceImageTableXrefs(const PEFile& pe, uint64_t imageBase,
                                      uint32_t maxStepsPerFunc) {
    XrefTraceResult result = {};
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    uint32_t rdataStart, rdataEnd, rdataRaw;
    uint32_t grfnStart, grfnEnd, grfnRaw;
    uint32_t grfnRawSz = findSection(pe, ".grfn1", grfnStart, grfnEnd, grfnRaw);
    findSection(pe, ".rdata", rdataStart, rdataEnd, rdataRaw);
    if (!grfnStart || !rdataStart) return result;

    auto isRdataVA = [&](uint64_t va) -> bool {
        if (va < imageBase) return false;
        uint32_t rva = (uint32_t)(va - imageBase);
        return rva >= rdataStart && rva < rdataEnd;
    };

    auto isValidFuncRVA = [&](uint32_t rva) -> bool {
        if (rva == 0 || rva >= soi) return false;
        uint32_t off = pe.rvaToOffset(rva);
        if (!off || off >= pe.data.size()) return false;
        uint8_t b = pe.data[off];
        return b != 0x00 && b != 0xCC;
    };

    std::unordered_set<uint32_t> tableEntries;
    for (uint32_t pos = 0; pos + 36 <= grfnRawSz; pos += 4) {
        const uint8_t* p = pe.data.data() + grfnRaw + pos;
        uint32_t v0 = *(uint32_t*)p;
        uint32_t v1 = *(uint32_t*)(p + 4);
        uint32_t v2 = *(uint32_t*)(p + 8);
        uint32_t next0 = *(uint32_t*)(p + 12);
        uint32_t next0b = *(uint32_t*)(p + 24);

        if (v0 == next0 && v0 == next0b && v0 != v1 && v0 != v2) {
            if (isValidFuncRVA(v1)) tableEntries.insert(v1);
            if (isValidFuncRVA(v2)) tableEntries.insert(v2);
        }
    }

    std::vector<uint32_t> funcs(tableEntries.begin(), tableEntries.end());
    std::mutex mtx;
    std::unordered_set<uint64_t> seen;
    std::atomic<uint32_t> idx{0};
    std::atomic<uint32_t> aHadCalls{0}, aTotalSteps{0};

    uint32_t numThreads = std::min(std::thread::hardware_concurrency(), 8u);
    if (numThreads < 1) numThreads = 4;

    auto worker = [&]() {
        while (true) {
            uint32_t i = idx.fetch_add(1);
            if (i >= funcs.size()) break;

            Tracer tracer(pe, imageBase);
            tracer.setSkipExternalCalls(true);
            tracer.setMaxVisitPerAddr(32);
            tracer.setProgressTimeout(1000);
            auto tr = tracer.trace(funcs[i], maxStepsPerFunc);
            aTotalSteps += (uint32_t)tr.stepsExecuted;
            if (!tr.calls.empty()) aHadCalls++;
            if (tr.calls.empty()) continue;

            std::lock_guard<std::mutex> lk(mtx);
            for (auto& call : tr.calls) {
                uint32_t callerRVA = (uint32_t)(call.callerVA - imageBase);
                for (int r = 0; r < 16; r++) {
                    if (r == (int)Reg::RSP) continue;
                    if (!isRdataVA(call.regs[r])) continue;
                    uint32_t targetRVA = (uint32_t)(call.regs[r] - imageBase);
                    uint64_t key = ((uint64_t)callerRVA << 32) | targetRVA;
                    if (!seen.insert(key).second) continue;
                    result.xrefs.push_back({callerRVA, targetRVA, call.regs[r]});
                }
            }
        }
    };

    std::vector<std::thread> threads;
    for (uint32_t t = 0; t < numThreads; t++) threads.emplace_back(worker);
    for (auto& t : threads) t.join();

    result.functionsTraced = (uint32_t)funcs.size();
    result.totalSteps = aTotalSteps.load();
    result.hadCalls = aHadCalls.load();
    return result;
}


XrefTraceResult traceDispatchKeys(const PEFile& pe, uint64_t imageBase,
                                   const std::vector<DispatchEntry>& entries,
                                   uint32_t maxStepsPerFunc) {
    XrefTraceResult result = {};
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    uint32_t rdataStart = 0, rdataEnd = 0, rdataRaw = 0;
    findSection(pe, ".rdata", rdataStart, rdataEnd, rdataRaw);

    auto isRdataVA = [&](uint64_t va) -> bool {
        if (va < imageBase) return false;
        uint32_t rva = (uint32_t)(va - imageBase);
        return rva >= rdataStart && rva < rdataEnd;
    };

    std::unordered_set<uint64_t> seen;

    for (auto& entry : entries) {
        Tracer tracer(pe, imageBase);
        tracer.setReg(entry.keyReg, (uint64_t)entry.key);

        if (entry.firstImulRVA != 0 && !entry.imulConsts.empty())
            tracer.addRegOverride(entry.firstImulRVA, entry.keyReg, (uint64_t)(uint32_t)entry.key);

        auto tr = tracer.trace(entry.funcRVA, maxStepsPerFunc);
        result.functionsTraced++;
        result.totalSteps += (uint32_t)tr.stepsExecuted;
        if (!tr.calls.empty()) result.hadCalls++;

        for (auto& call : tr.calls) {
            uint32_t callerRVA = (uint32_t)(call.callerVA - imageBase);
            for (int r = 0; r < 16; r++) {
                if (r == (int)Reg::RSP) continue;
                if (!isRdataVA(call.regs[r])) continue;
                uint32_t targetRVA = (uint32_t)(call.regs[r] - imageBase);
                uint64_t key = ((uint64_t)callerRVA << 32) | targetRVA;
                if (!seen.insert(key).second) continue;
                result.xrefs.push_back({callerRVA, targetRVA, call.regs[r]});
            }
        }
    }
    return result;
}


DebugTraceResult debugTraceSingle(const PEFile& pe, uint64_t imageBase,
                                   const DispatchEntry& entry,
                                   uint32_t maxSteps, uint32_t logLimit) {
    DebugTraceResult result;
    Tracer tracer(pe, imageBase);
    tracer.setReg(entry.keyReg, (uint64_t)entry.key);
    tracer.setTraceLog([&](const pefix::TraceStep& ts) {
        result.steps.push_back(ts);
    }, logLimit);

    auto tr = tracer.trace(entry.funcRVA, maxSteps);
    result.calls = std::move(tr.calls);
    result.stepsExecuted = tr.stepsExecuted;
    result.stopReason = std::move(tr.stopReason);
    return result;
}

} // namespace griffin
