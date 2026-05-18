#pragma once
#include <pefix/pe.h>
#include <cstdint>
#include <vector>

namespace griffin {

enum class DispatcherKind : uint8_t {
    // 8F 84 24 disp32  E9 disp32   (12 bytes)
    PopJmp = 0,
    // [48] E9 disp32  CC{minPaddingLen+}
    // Off by default: on vgc this matched only stray E9 inside function
    // padding (100% false-positive in 2026-05-18 measurement).
    JmpCCpad = 1,
};

struct JumpDispatcher {
    uint32_t sourceRVA;
    uint32_t targetRVA;
    uint32_t directRVA;     // before transitive chase
    uint8_t  prefixLen;     // JmpCCpad: 0 = E9, 1 = 48 E9
    uint8_t  paddingLen;    // JmpCCpad: trailing CC count
    uint8_t  inSectionIdx;
    uint8_t  chainDepth;
    DispatcherKind kind;
};

struct PfrStats {
    uint32_t totalBytesScanned = 0;
    uint32_t directEntries = 0;
    uint32_t finalEntries = 0;
    uint32_t popJmpEntries = 0;
    uint32_t jmpCCpadEntries = 0;
    uint32_t targetsToText = 0;
    uint32_t targetsToGrfn = 0;
    uint32_t targetsToRiot = 0;
    uint32_t targetsOutOfImage = 0;
    uint32_t cyclesDropped = 0;
    uint32_t durationMs = 0;
};

struct PfrConfig {
    bool     scanPopJmp = true;
    bool     scanJmpCCpad = false;
    uint8_t  minPaddingLen = 4;
    bool     allowRexPrefix = true;
    bool     scanText = false;
    bool     scanGrfn1 = true;
    bool     scanRiot = true;
    uint32_t maxChainDepth = 16;
};

struct PfrResult {
    std::vector<JumpDispatcher> dispatchers;
    PfrStats stats;

    const JumpDispatcher* findSource(uint32_t sourceRVA) const;
};

PfrResult extractJumpDispatchers(const pefix::PEFile& pe,
                                  uint64_t imageBase,
                                  const PfrConfig& cfg = {});

} // namespace griffin
