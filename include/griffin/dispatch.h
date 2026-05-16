#pragma once
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <pefix/xrefs.h>
#include <cstdint>
#include <vector>

namespace griffin {

using DispatchKey = pefix::DispatchKey;

struct DispatchKeyResult {
    uint64_t callerVA;
    uint32_t callerRVA;
    int64_t dispatchKey;
    bool found;
    pefix::Reg keyReg;
};

struct MultiKeyResult {
    std::vector<DispatchKey> keys;
    int imulTotal;
};

class DispatchExtractor {
public:
    DispatchExtractor(const pefix::PEFile& pe, uint64_t imageBase);

    std::vector<DispatchKeyResult> extractKeys(
        uint32_t targetRVA,
        const std::vector<pefix::RipRelativeRef>& allRefs);

    DispatchKeyResult extractFromCallSite(uint32_t callRVA);
    DispatchKeyResult extractFromConstraints(pefix::Func& func);
    MultiKeyResult extractAllKeys(pefix::Func& func);

private:
    const pefix::PEFile& pe_;
    uint64_t imageBase_;

    bool disasmBackward(uint32_t endRVA, uint32_t maxBytes, std::vector<pefix::Instr>& instrs);
    bool resolveRegAtEnd(const std::vector<pefix::Instr>& instrs, pefix::Reg reg, int64_t& value);
};

} // namespace griffin
