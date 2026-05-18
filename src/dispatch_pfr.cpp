#include <griffin/dispatch_pfr.h>
#include <griffin/log.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace griffin {

namespace {

bool sectionWanted(const char* name, const PfrConfig& cfg) {
    if (strcmp(name, ".text") == 0) return cfg.scanText;
    if (strcmp(name, ".grfn1") == 0) return cfg.scanGrfn1;
    if (strncmp(name, ".riot", 5) == 0) return cfg.scanRiot;
    return false;
}

int32_t readDisp32(const uint8_t* p) {
    int32_t v;
    memcpy(&v, p, 4);
    return v;
}

} // namespace

const JumpDispatcher* PfrResult::findSource(uint32_t sourceRVA) const {
    auto it = std::lower_bound(dispatchers.begin(), dispatchers.end(), sourceRVA,
        [](const JumpDispatcher& d, uint32_t r) { return d.sourceRVA < r; });
    if (it != dispatchers.end() && it->sourceRVA == sourceRVA) return &*it;
    return nullptr;
}

PfrResult extractJumpDispatchers(const pefix::PEFile& pe,
                                  uint64_t imageBase,
                                  const PfrConfig& cfg) {
    (void)imageBase;
    auto t0 = std::chrono::high_resolution_clock::now();
    PfrResult result;
    PfrStats& st = result.stats;
    if (!pe.nt) return result;

    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    // inSectionIdx in JumpDispatcher refers to this vector's index, which
    // matches PE section ordering 1:1.
    struct SectionInfo {
        uint32_t va, vsize, rawOff, rawSize;
        char     name[9];
        bool     isExec;
        uint8_t  idx;
    };
    std::vector<SectionInfo> sections;
    for (WORD i = 0; i < pe.numSections; i++) {
        SectionInfo si{};
        si.va = pe.sections[i].VirtualAddress;
        si.vsize = pe.sections[i].Misc.VirtualSize;
        si.rawOff = pe.sections[i].PointerToRawData;
        si.rawSize = pe.sections[i].SizeOfRawData;
        memcpy(si.name, pe.sections[i].Name, 8);
        si.isExec = (pe.sections[i].Characteristics & 0x20000000) != 0;
        si.idx = (uint8_t)i;
        sections.push_back(si);
    }

    auto findSectionIdx = [&](uint32_t rva) -> int {
        for (size_t i = 0; i < sections.size(); i++)
            if (rva >= sections[i].va && rva < sections[i].va + sections[i].vsize)
                return (int)i;
        return -1;
    };

    // Step 1: raw pattern matching.
    std::vector<JumpDispatcher> raw;
    auto validateTarget = [&](uint32_t directRVA) -> int {
        if (directRVA >= soi) { st.targetsOutOfImage++; return -1; }
        int tSec = findSectionIdx(directRVA);
        if (tSec < 0 || !sections[tSec].isExec) {
            st.targetsOutOfImage++;
            return -1;
        }
        return tSec;
    };
    for (auto& sec : sections) {
        if (!sec.isExec) continue;
        if (!sectionWanted(sec.name, cfg)) continue;
        uint32_t scanLen = std::min(sec.vsize, sec.rawSize);
        if (sec.rawOff + scanLen > pe.data.size())
            scanLen = (uint32_t)pe.data.size() - sec.rawOff;
        st.totalBytesScanned += scanLen;

        const uint8_t* base = pe.data.data() + sec.rawOff;
        for (uint32_t pos = 0; pos + 5 < scanLen; pos++) {
            uint8_t b0 = base[pos];

            // PopJmp: 8F 84 24 disp32  E9 disp32  (pop [rsp+disp32]; jmp rel32)
            if (cfg.scanPopJmp && b0 == 0x8F && pos + 12 <= scanLen &&
                base[pos + 1] == 0x84 && base[pos + 2] == 0x24 &&
                base[pos + 7] == 0xE9) {
                int32_t disp = readDisp32(base + pos + 8);
                uint32_t srcRVA = sec.va + pos;
                uint32_t directRVA = srcRVA + 12 + (uint32_t)disp;
                if (validateTarget(directRVA) < 0) continue;

                JumpDispatcher d{};
                d.sourceRVA = srcRVA;
                d.directRVA = directRVA;
                d.targetRVA = directRVA;
                d.prefixLen = 0;
                d.paddingLen = 0;
                d.inSectionIdx = sec.idx;
                d.chainDepth = 1;
                d.kind = DispatcherKind::PopJmp;
                raw.push_back(d);
                st.popJmpEntries++;
                pos += 11; // for-loop +1 lands at next byte after trampoline
                continue;
            }

            // JmpCCpad: [48] E9 disp32  CC{minPaddingLen+}
            if (!cfg.scanJmpCCpad) continue;
            uint8_t prefix = 0;
            uint32_t jmpAt = pos;
            if (cfg.allowRexPrefix && b0 == 0x48 && pos + 6 < scanLen && base[pos + 1] == 0xE9) {
                prefix = 1;
                jmpAt = pos + 1;
            } else if (b0 != 0xE9) {
                continue;
            }

            uint32_t jmpEnd = jmpAt + 5;
            if (jmpEnd + cfg.minPaddingLen > scanLen) continue;

            uint8_t padLen = 0;
            while (jmpEnd + padLen < scanLen && base[jmpEnd + padLen] == 0xCC && padLen < 32)
                padLen++;
            if (padLen < cfg.minPaddingLen) continue;

            int32_t disp = readDisp32(base + jmpAt + 1);
            uint32_t srcRVA = sec.va + pos;
            uint32_t instrLen = prefix ? 6 : 5;
            uint32_t directRVA = srcRVA + instrLen + (uint32_t)disp;
            if (validateTarget(directRVA) < 0) continue;

            JumpDispatcher d{};
            d.sourceRVA = srcRVA;
            d.directRVA = directRVA;
            d.targetRVA = directRVA;
            d.prefixLen = prefix;
            d.paddingLen = padLen;
            d.inSectionIdx = sec.idx;
            d.chainDepth = 1;
            d.kind = DispatcherKind::JmpCCpad;
            raw.push_back(d);
            st.jmpCCpadEntries++;
            pos = jmpAt + 5 + padLen - 1;
        }
    }
    st.directEntries = (uint32_t)raw.size();

    // Step 2: transitive chase. Sort enables O(log N) lookup.
    std::sort(raw.begin(), raw.end(),
        [](const JumpDispatcher& a, const JumpDispatcher& b) {
            return a.sourceRVA < b.sourceRVA;
        });
    auto lookup = [&](uint32_t srcRVA) -> JumpDispatcher* {
        auto it = std::lower_bound(raw.begin(), raw.end(), srcRVA,
            [](const JumpDispatcher& d, uint32_t r) { return d.sourceRVA < r; });
        if (it != raw.end() && it->sourceRVA == srcRVA) return &*it;
        return nullptr;
    };

    for (auto& d : raw) {
        std::unordered_set<uint32_t> visited;
        visited.insert(d.sourceRVA);
        uint32_t cur = d.directRVA;
        uint32_t depth = 1;
        while (depth < cfg.maxChainDepth) {
            JumpDispatcher* nxt = lookup(cur);
            if (!nxt) break;
            if (!visited.insert(cur).second) { st.cyclesDropped++; cur = d.directRVA; depth = 1; break; }
            cur = nxt->directRVA;
            depth++;
        }
        d.targetRVA = cur;
        d.chainDepth = (uint8_t)depth;
    }

    // Step 3: classify final targets by section.
    for (auto& d : raw) {
        int s = findSectionIdx(d.targetRVA);
        if (s < 0) { st.targetsOutOfImage++; continue; }
        const char* n = sections[s].name;
        if (strcmp(n, ".text") == 0) st.targetsToText++;
        else if (strcmp(n, ".grfn1") == 0) st.targetsToGrfn++;
        else if (strncmp(n, ".riot", 5) == 0) st.targetsToRiot++;
    }

    result.dispatchers = std::move(raw);
    st.finalEntries = (uint32_t)result.dispatchers.size();

    auto t1 = std::chrono::high_resolution_clock::now();
    st.durationMs = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    log::ok("PFR: scanned %u bytes, %u entries (popJmp=%u jmpCCpad=%u) "
            "(->text %u, ->grfn %u, ->riot %u), cycles %u, %ums",
            st.totalBytesScanned, st.finalEntries,
            st.popJmpEntries, st.jmpCCpadEntries,
            st.targetsToText, st.targetsToGrfn, st.targetsToRiot,
            st.cyclesDropped, st.durationMs);

    return result;
}

} // namespace griffin
