#include <griffin/dispatch.h>
#include <griffin/mba.h>
#include <pefix/x86_64/disasm.h>
#ifdef GRIFFIN_USE_Z3
#include <z3++.h>
#endif
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <set>
#include <map>

namespace griffin {

using namespace pefix;

DispatchExtractor::DispatchExtractor(const PEFile& pe, uint64_t imageBase)
    : pe_(pe), imageBase_(imageBase) {}

std::vector<DispatchKeyResult> DispatchExtractor::extractKeys(
    uint32_t targetRVA,
    const std::vector<RipRelativeRef>& allRefs) {

    std::vector<DispatchKeyResult> results;
    uint64_t targetVA = imageBase_ + targetRVA;
    uint32_t sizeOfImage = pe_.nt->OptionalHeader.SizeOfImage;

    for (auto& ref : allRefs) {
        if (!ref.isCall) continue;
        if (ref.targetVA != targetVA && ref.targetRVA != targetRVA) continue;

        auto dk = extractFromCallSite(ref.instrRVA);
        dk.callerRVA = ref.instrRVA;
        dk.callerVA = imageBase_ + ref.instrRVA;
        results.push_back(dk);
    }

    for (int si = 0; si < pe_.numSections; si++) {
        if (!pe_.isExecutableSection(si)) continue;
        uint32_t secRVA = pe_.sections[si].VirtualAddress;
        uint32_t rawOff = pe_.sections[si].PointerToRawData;
        uint32_t rawSz = pe_.sections[si].SizeOfRawData;

        for (uint32_t pos = 0; pos + 5 <= rawSz; pos++) {
            if (pe_.data[rawOff + pos] != 0xE8) continue;

            uint32_t callRVA = secRVA + pos;
            int32_t disp = *(int32_t*)(pe_.data.data() + rawOff + pos + 1);
            uint32_t directTarget = callRVA + 5 + disp;

            bool match = (directTarget == targetRVA);

            if (!match && directTarget < sizeOfImage) {
                uint32_t cur = directTarget;
                for (int hop = 0; hop < 8 && !match; hop++) {
                    uint32_t off = pe_.rvaToOffset(cur);
                    if (!off || off + 5 > pe_.data.size()) break;
                    if (pe_.data[off] != 0xE9) break;
                    int32_t jdisp = *(int32_t*)(pe_.data.data() + off + 1);
                    cur = cur + 5 + jdisp;
                    if (cur >= sizeOfImage) break;
                    if (cur == targetRVA) match = true;
                }
            }

            if (!match) continue;

            bool dup = false;
            for (auto& r : results)
                if (r.callerRVA == callRVA) { dup = true; break; }
            if (dup) continue;

            auto dk = extractFromCallSite(callRVA);
            dk.callerRVA = callRVA;
            dk.callerVA = imageBase_ + callRVA;
            results.push_back(dk);
        }
    }

    return results;
}

bool DispatchExtractor::disasmBackward(uint32_t endRVA, uint32_t maxBytes,
                                        std::vector<Instr>& instrs) {
    uint32_t funcStartRVA = 0;
    int pdataSec = -1;
    for (int i = 0; i < pe_.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe_.sections[i].Name, 8);
        if (strcmp(name, ".pdata") == 0) { pdataSec = i; break; }
    }

    if (pdataSec >= 0) {
        uint32_t pdataOff = pe_.sections[pdataSec].PointerToRawData;
        uint32_t pdataSize = pe_.sections[pdataSec].SizeOfRawData;
        uint32_t count = pdataSize / 12;
        const uint8_t* pdata = pe_.data.data() + pdataOff;

        for (uint32_t i = 0; i < count; i++) {
            uint32_t begin = *(uint32_t*)(pdata + i * 12);
            uint32_t end = *(uint32_t*)(pdata + i * 12 + 4);
            if (endRVA >= begin && endRVA < end) {
                funcStartRVA = begin;
                break;
            }
        }
    }

    if (funcStartRVA == 0) {
        uint32_t searchStart = (endRVA > maxBytes) ? endRVA - maxBytes : 0;
        funcStartRVA = searchStart;
    }

    Disasm disasm(pe_, imageBase_);

    uint32_t rva = funcStartRVA;
    while (rva < endRVA) {
        uint32_t off = pe_.rvaToOffset(rva);
        if (!off || off >= pe_.data.size()) break;

        Instr instr;
        uint32_t len = disasm.decodeOne(off, imageBase_ + rva, instr);
        if (len == 0) { rva++; continue; }

        instr.addr = imageBase_ + rva;
        instr.rawLen = len;
        instrs.push_back(instr);
        rva += len;
    }

    return !instrs.empty();
}

bool DispatchExtractor::resolveRegAtEnd(const std::vector<Instr>& instrs,
                                          Reg reg, int64_t& value) {
    AbstractValue regs[16];
    for (int i = 0; i < 16; i++) regs[i] = AbstractValue::Top();
    regs[(int)Reg::RSP] = AbstractValue::MkConst(0, Width::W64);

    for (auto& instr : instrs) {
        if (instr.dead) continue;

        auto getAV = [&](const Value& v) -> AbstractValue {
            if (v.kind == Value::IMM)
                return AbstractValue::MkConst((uint64_t)v.imm, v.width);
            if (v.kind == Value::REG && (uint16_t)v.reg < 16)
                return regs[(uint16_t)v.reg];
            return AbstractValue::Top();
        };

        auto setAV = [&](const Value& v, AbstractValue av) {
            if (v.kind == Value::REG && (uint16_t)v.reg < 16) {
                if (v.width == Width::W32) av.value &= 0xFFFFFFFF;
                regs[(uint16_t)v.reg] = av;
            }
        };

        AbstractValue s1 = getAV(instr.src1);
        AbstractValue s2 = getAV(instr.src2);

        switch (instr.op) {
        case Op::MOV:
            setAV(instr.dst, s1);
            break;
        case Op::MOVZX:
            setAV(instr.dst, s1);
            break;
        case Op::LEA:
            if (instr.src1.isMem()) {
                AbstractValue base = (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
                    ? regs[(uint16_t)instr.src1.reg] : AbstractValue::Top();
                AbstractValue idx = (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
                    ? regs[(uint16_t)instr.src1.index] : AbstractValue::Top();
                if (base.isConst() && (instr.src1.index == Reg::NONE || idx.isConst())) {
                    uint64_t r = base.value + instr.src1.imm;
                    if (instr.src1.index != Reg::NONE)
                        r += idx.value * (instr.src1.scale ? instr.src1.scale : 1);
                    setAV(instr.dst, AbstractValue::MkConst(r, instr.dst.width));
                } else {
                    setAV(instr.dst, AbstractValue::Top());
                }
            }
            break;
        case Op::ADD:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() + s2.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::SUB:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() - s2.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::IMUL:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() * s2.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::AND:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() & s2.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::OR:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() | s2.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::XOR:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() ^ s2.masked(), instr.dst.width));
            else if (instr.src1.isReg() && instr.src2.isReg() && instr.src1.reg == instr.src2.reg)
                setAV(instr.dst, AbstractValue::MkConst(0, instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::NOT:
            if (s1.isConst())
                setAV(instr.dst, AbstractValue::MkConst(~s1.masked(), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::SHL:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() << (s2.value & 63), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::SHR:
            if (s1.isConst() && s2.isConst())
                setAV(instr.dst, AbstractValue::MkConst(s1.masked() >> (s2.value & 63), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::NEG:
            if (s1.isConst())
                setAV(instr.dst, AbstractValue::MkConst((uint64_t)(-(int64_t)s1.masked()), instr.dst.width));
            else setAV(instr.dst, AbstractValue::Top());
            break;
        case Op::CALL:
            for (int r : {0, 1, 2, 8, 9, 10, 11})
                regs[r] = AbstractValue::Top();
            break;
        default:
            if (!instr.dst.isNone()) setAV(instr.dst, AbstractValue::Top());
            break;
        }
    }

    uint16_t regIdx = (uint16_t)reg;
    if (regIdx < 16 && regs[regIdx].isConst()) {
        value = (int64_t)regs[regIdx].value;
        return true;
    }
    return false;
}

DispatchKeyResult DispatchExtractor::extractFromCallSite(uint32_t callRVA) {
    DispatchKeyResult result = {};
    result.found = false;
    result.keyReg = Reg::RDI;

    std::vector<Instr> instrs;
    if (!disasmBackward(callRVA, 0x1000, instrs))
        return result;

    int64_t value = 0;
    if (resolveRegAtEnd(instrs, Reg::RDI, value)) {
        result.found = true;
        result.dispatchKey = value;
        return result;
    }

    // Try r12d
    if (resolveRegAtEnd(instrs, Reg::R12, value)) {
        result.found = true;
        result.dispatchKey = value;
        result.keyReg = Reg::R12;
        return result;
    }

    return result;
}

static uint32_t modInverse32(uint32_t a) {
    uint32_t x = a;
    for (int i = 0; i < 5; i++)
        x = x * (2 - a * x);
    return x;
}

static bool solveDispatchKey(const std::set<uint32_t>& consts, uint32_t threshold,
                              uint32_t& outKey) {
    if (consts.size() < 2) return false;

    uint32_t pivot = 0;
    int pivotShift = 0;
    for (uint32_t c : consts) {
        uint32_t tmp = c;
        int shift = 0;
        while ((tmp & 1) == 0 && shift < 31) { tmp >>= 1; shift++; }
        if (shift < pivotShift || pivot == 0) {
            pivot = c;
            pivotShift = shift;
        }
    }

    if (pivot == 0) return false;

    uint32_t oddPart = pivot >> pivotShift;
    uint32_t inv = modInverse32(oddPart);
    uint32_t effThreshold = threshold >> pivotShift;
    if (effThreshold == 0) effThreshold = 1;

    std::vector<uint32_t> verifyConsts;
    for (uint32_t c : consts)
        if (c != pivot) verifyConsts.push_back(c);

    for (uint32_t k = 1; k < effThreshold; k++) {
        uint32_t edi = k * inv;
        if (edi == 0) continue;
        if ((edi & (edi - 1)) == 0) continue;

        bool valid = true;
        for (uint32_t c : verifyConsts) {
            uint32_t product = edi * c;
            if (product >= threshold * 2) { valid = false; break; }
        }
        if (!valid) continue;

        std::set<uint32_t> products;
        for (uint32_t c : consts) products.insert(edi * c);
        if (products.size() < 2) continue;

        outKey = edi;
        return true;
    }

    return false;
}

DispatchKeyResult DispatchExtractor::extractFromConstraints(Func& func) {
    DispatchKeyResult result = {};
    result.found = false;
    result.keyReg = Reg::RDI;

    std::map<uint16_t, std::set<uint32_t>> regImulConsts;
    for (auto& blk : func.blocks) {
        for (auto& instr : blk.instrs) {
            if (instr.dead) continue;
            if (instr.op != Op::IMUL) continue;
            if (!instr.src1.isReg() || !instr.src2.isImm()) continue;
            uint16_t srcReg = (uint16_t)instr.src1.reg;
            if (srcReg >= 16) continue;
            uint32_t c = (uint32_t)(uint64_t)instr.src2.imm;
            if (c == 0 || c == 1) continue;
            regImulConsts[srcReg].insert(c);
        }
    }

    uint16_t bestReg = 0xFFFF;
    size_t bestCount = 0;
    for (auto& [reg, consts] : regImulConsts) {
        if (consts.size() > bestCount) {
            bestCount = consts.size();
            bestReg = reg;
        }
    }

    if (bestReg == 0xFFFF || bestCount < 2) {
        return result;
    }

    result.keyReg = (Reg)bestReg;
    std::set<uint32_t>& imulConsts = regImulConsts[bestReg];

    uint32_t key = 0;
    if (solveDispatchKey(imulConsts, 0x1000, key)) {
        result.found = true;
        result.dispatchKey = (int64_t)key;
        return result;
    }
    if (solveDispatchKey(imulConsts, 0x2000, key)) {
        result.found = true;
        result.dispatchKey = (int64_t)key;
        return result;
    }
    if (bestCount <= 3 && solveDispatchKey(imulConsts, 0x4000, key)) {
        result.found = true;
        result.dispatchKey = (int64_t)key;
        return result;
    }

    return result;
}

struct ImulInfo {
    uint16_t srcReg;
    uint32_t constant;
    uint32_t rva;
};

static void collectImulPatterns(const Func& func, uint64_t imageBase,
                                 std::map<uint16_t, std::set<uint32_t>>& regConsts,
                                 std::vector<ImulInfo>& allImuls) {
    for (auto& blk : func.blocks) {
        for (auto& instr : blk.instrs) {
            if (instr.dead) continue;
            if (instr.op != Op::IMUL) continue;
            if (!instr.src1.isReg() || !instr.src2.isImm()) continue;
            uint16_t srcReg = (uint16_t)instr.src1.reg;
            if (srcReg >= 16) continue;
            uint32_t c = (uint32_t)(uint64_t)instr.src2.imm;
            if (c == 0 || c == 1) continue;
            regConsts[srcReg].insert(c);
            uint32_t rva = instr.addr ? (uint32_t)(instr.addr - imageBase) : 0;
            allImuls.push_back({srcReg, c, rva});
        }
    }
}

MultiKeyResult DispatchExtractor::extractAllKeys(Func& func) {
    MultiKeyResult result = {};
    result.imulTotal = 0;

    std::map<uint16_t, std::set<uint32_t>> regConsts;
    std::vector<ImulInfo> allImuls;
    collectImulPatterns(func, imageBase_, regConsts, allImuls);

    for (auto& [reg, consts] : regConsts) {
        result.imulTotal += (int)consts.size();
        if (consts.size() < 3) continue;
        if (reg == (uint16_t)Reg::RSP) continue;

        uint32_t key = 0;
        bool found = false;

        for (uint32_t thresh : {0x1000u, 0x2000u, 0x4000u}) {
            if (solveDispatchKey(consts, thresh, key)) {
                found = true;
                break;
            }
        }

        if (found) {
            DispatchKey dk;
            dk.reg = (Reg)reg;
            dk.value = key;
            dk.imulConsts.assign(consts.begin(), consts.end());
            for (auto& im : allImuls) {
                if (im.srcReg == reg && im.rva != 0) {
                    dk.firstImulRVA = im.rva;
                    break;
                }
            }
            result.keys.push_back(dk);
        }
    }

    return result;
}

} // namespace griffin
