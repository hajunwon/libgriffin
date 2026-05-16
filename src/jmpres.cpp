#include <griffin/jmpres.h>
#include <pefix/x86_64/disasm.h>
#include <cstring>
#include <cstdio>
#include <set>
#include <unordered_set>

namespace griffin {

using namespace pefix;

struct RegTracker {
    uint64_t regs[16] = {};
    bool known[16] = {};
    const PEFile* pe = nullptr;
    uint64_t imageBase = 0;

    void setConst(int r, uint64_t v) { if (r < 16) { regs[r] = v; known[r] = true; } }
    void invalidate(int r) { if (r < 16) known[r] = false; }
    bool isKnown(int r) const { return r < 16 && known[r]; }

    bool readMem(uint64_t va, uint64_t& out, int size = 8) const {
        if (!pe) return false;
        uint32_t rva = (uint32_t)(va - imageBase);
        uint32_t off = pe->rvaToOffset(rva);
        if (!off || off + size > pe->data.size()) return false;
        int sec = pe->findSection(rva);
        if (sec >= 0 && (pe->sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) return false;
        if (size == 8) out = *(uint64_t*)(pe->data.data() + off);
        else if (size == 4) out = *(uint32_t*)(pe->data.data() + off);
        else return false;
        return true;
    }
};

static void trackInstr(RegTracker& rt, const uint8_t* code, uint32_t len, uint32_t instrRVA) {
    if (len < 2) return;
    uint8_t rex = 0;
    int pos = 0;
    if ((code[0] & 0xF0) == 0x40) { rex = code[0]; pos = 1; }
    bool rexW = (rex & 0x08) != 0;
    bool rexR = (rex & 0x04) != 0;
    bool rexB = (rex & 0x01) != 0;

    if (code[pos] >= 0xB8 && code[pos] <= 0xBF) {
        int reg = (code[pos] & 7) + (rexB ? 8 : 0);
        if (rexW && pos + 9 <= (int)len)
            rt.setConst(reg, *(uint64_t*)(code + pos + 1));
        else if (pos + 5 <= (int)len)
            rt.setConst(reg, *(uint32_t*)(code + pos + 1));
        return;
    }

    if (code[pos] == 0x8D && pos + 3 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        uint8_t regField = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
        uint8_t rm = (modrm & 7) + (rexB ? 8 : 0);
        uint8_t mod = modrm >> 6;

        if ((modrm & 0xC7) == 0x05) {
            int32_t disp = *(int32_t*)(code + pos + 2);
            rt.setConst(regField, instrRVA + len + disp);
            return;
        }
        if (mod == 2 && (modrm & 7) != 4 && pos + 6 <= (int)len) {
            if (rt.isKnown(rm)) {
                int32_t disp = *(int32_t*)(code + pos + 2);
                uint64_t result = rt.regs[rm] + disp;
                if (!rexW) result &= 0xFFFFFFFF;
                rt.setConst(regField, result);
                return;
            }
        }
        if (mod == 1 && (modrm & 7) != 4 && pos + 3 <= (int)len) {
            if (rt.isKnown(rm)) {
                int8_t disp = (int8_t)code[pos + 2];
                uint64_t result = rt.regs[rm] + disp;
                if (!rexW) result &= 0xFFFFFFFF;
                rt.setConst(regField, result);
                return;
            }
        }
    }

    if (code[pos] == 0x8B && pos + 2 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        uint8_t mod = modrm >> 6;
        int dst = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
        int rm2 = (modrm & 7) + (rexB ? 8 : 0);

        if ((modrm & 0xC7) == 0x05 && pos + 6 <= (int)len) {
            int32_t disp = *(int32_t*)(code + pos + 2);
            uint64_t addr = instrRVA + len + disp;
            uint64_t val = 0;
            if (rt.readMem(addr + rt.imageBase, val, rexW ? 8 : 4))
                rt.setConst(dst, val);
            else
                rt.invalidate(dst);
            return;
        }
        if (mod == 0 && (modrm & 7) != 4 && (modrm & 7) != 5) {
            if (rt.isKnown(rm2)) {
                uint64_t val = 0;
                if (rt.readMem(rt.regs[rm2], val, rexW ? 8 : 4))
                    rt.setConst(dst, val);
                else
                    rt.invalidate(dst);
            } else rt.invalidate(dst);
            return;
        }
        if (mod == 1 && (modrm & 7) != 4 && pos + 3 <= (int)len) {
            if (rt.isKnown(rm2)) {
                int8_t d8 = (int8_t)code[pos + 2];
                uint64_t val = 0;
                if (rt.readMem(rt.regs[rm2] + d8, val, rexW ? 8 : 4))
                    rt.setConst(dst, val);
                else
                    rt.invalidate(dst);
            } else rt.invalidate(dst);
            return;
        }
        if (mod == 2 && (modrm & 7) != 4 && pos + 6 <= (int)len) {
            if (rt.isKnown(rm2)) {
                int32_t d32 = *(int32_t*)(code + pos + 2);
                uint64_t val = 0;
                if (rt.readMem(rt.regs[rm2] + d32, val, rexW ? 8 : 4))
                    rt.setConst(dst, val);
                else
                    rt.invalidate(dst);
            } else rt.invalidate(dst);
            return;
        }
        if (mod == 3) {
            if (rt.isKnown(rm2))
                rt.setConst(dst, rt.regs[rm2]);
            else
                rt.invalidate(dst);
            return;
        }
    }

    if (code[pos] == 0x69 && pos + 6 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        if ((modrm >> 6) == 3) {
            int dst = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
            int src = (modrm & 7) + (rexB ? 8 : 0);
            if (rt.isKnown(src)) {
                uint32_t imm = *(uint32_t*)(code + pos + 2);
                rt.setConst(dst, (uint32_t)(rt.regs[src] * imm));
                return;
            }
        }
    }

    if (code[pos] == 0x81 && pos + 6 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        if ((modrm >> 6) == 3 && ((modrm >> 3) & 7) == 0) {
            int reg = (modrm & 7) + (rexB ? 8 : 0);
            if (rt.isKnown(reg)) {
                int32_t imm = *(int32_t*)(code + pos + 2);
                rt.setConst(reg, rexW ? rt.regs[reg] + imm : (uint32_t)(rt.regs[reg] + imm));
                return;
            }
        }
    }

    if (code[pos] == 0x83 && pos + 3 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        if ((modrm >> 6) == 3 && ((modrm >> 3) & 7) == 0) {
            int reg = (modrm & 7) + (rexB ? 8 : 0);
            if (rt.isKnown(reg)) {
                int8_t imm = (int8_t)code[pos + 2];
                rt.setConst(reg, rexW ? rt.regs[reg] + imm : (uint32_t)(rt.regs[reg] + imm));
                return;
            }
        }
    }

    if ((code[pos] == 0x33 || code[pos] == 0x31) && pos + 2 <= (int)len) {
        uint8_t modrm = code[pos + 1];
        if ((modrm >> 6) == 3) {
            int r1 = ((modrm >> 3) & 7) + (rexR ? 8 : 0);
            int r2 = (modrm & 7) + (rexB ? 8 : 0);
            if (r1 == r2) { rt.setConst(r1, 0); return; }
            if (rt.isKnown(r1) && rt.isKnown(r2)) {
                rt.setConst(code[pos] == 0x33 ? r1 : r2, rt.regs[r1] ^ rt.regs[r2]);
                return;
            }
        }
    }
}

static uint32_t instrLen(const uint8_t* p, uint32_t maxLen) {
    if (maxLen < 1) return 0;
    uint32_t i = 0;
    while (i < maxLen && (p[i] == 0x66 || p[i] == 0xF2 || p[i] == 0xF3 ||
           p[i] == 0x26 || p[i] == 0x2E || p[i] == 0x36 || p[i] == 0x3E ||
           p[i] == 0x64 || p[i] == 0x65)) i++;
    if (i < maxLen && (p[i] & 0xF0) == 0x40) i++;
    if (i >= maxLen) return 0;
    uint8_t op = p[i++];
    bool twoByteOp = false;
    if (op == 0x0F) { if (i >= maxLen) return 0; op = p[i++]; twoByteOp = true; }
    if (!twoByteOp) {
        if ((op & 0xF8) == 0xB8) return i + 4;
        if ((op & 0xF8) == 0x50 || (op & 0xF8) == 0x58) return i;
        if (op == 0xC3 || op == 0xCB) return i;
        if (op == 0xE8 || op == 0xE9) return i + 4;
        if (op == 0xEB) return i + 1;
        if (op >= 0x70 && op <= 0x7F) return i + 1;
        if (op == 0xCC || op == 0x90) return i;
        if (op == 0xC6) {
            if (i >= maxLen) return 0;
            uint8_t modrm = p[i]; uint8_t mod = modrm >> 6;
            i++;
            if ((modrm & 7) == 4 && mod != 3) i++;
            if (mod == 1) i += 1; else if (mod == 2 || (mod == 0 && (modrm & 7) == 5)) i += 4;
            return i + 1;
        }
    }
    if (i >= maxLen) return 0;
    uint8_t modrm = p[i]; uint8_t mod = modrm >> 6; uint8_t rm = modrm & 7;
    i++;
    if (mod != 3 && rm == 4) i++;
    if (mod == 1) i += 1;
    else if (mod == 2) i += 4;
    else if (mod == 0 && rm == 5) i += 4;
    if (!twoByteOp && (op == 0x69)) i += 4;
    if (!twoByteOp && (op == 0x6B)) i += 1;
    if (!twoByteOp && (op == 0x81)) i += 4;
    if (!twoByteOp && (op == 0x83)) i += 1;
    if (!twoByteOp && (op == 0xC7)) i += 4;
    return i <= maxLen ? i : 0;
}

std::vector<ResolvedJmp> resolveIndirectJumps(
    const PEFile& pe, uint64_t imageBase,
    const std::vector<uint32_t>& funcRVAs) {

    std::vector<ResolvedJmp> results;
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;
    std::unordered_set<uint32_t> funcSet(funcRVAs.begin(), funcRVAs.end());

    for (int si = 0; si < pe.numSections; si++) {
        char sname[9] = {};
        memcpy(sname, pe.sections[si].Name, 8);
        if (strcmp(sname, ".grfn1") != 0 && strcmp(sname, ".text") != 0) continue;

        uint32_t secRVA = pe.sections[si].VirtualAddress;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;

        for (auto funcRVA : funcRVAs) {
            if (funcRVA < secRVA || funcRVA >= secRVA + rawSz) continue;

            RegTracker rt;
            rt.pe = &pe;
            rt.imageBase = imageBase;
            uint32_t pos = funcRVA - secRVA;
            uint32_t maxInstrs = 200;

            for (uint32_t n = 0; n < maxInstrs && pos + 2 < rawSz; n++) {
                uint32_t off = rawOff + pos;
                const uint8_t* code = pe.data.data() + off;
                uint32_t remain = rawSz - pos;
                uint32_t iLen = instrLen(code, std::min(remain, (uint32_t)15));
                if (iLen == 0) break;

                uint32_t instrRVA = secRVA + pos;

                bool isJmpReg = false;
                uint8_t jmpLen = 0;
                int targetReg = -1;

                if (code[0] == 0xFF && (code[1] & 0xF8) == 0xE0) {
                    isJmpReg = true; jmpLen = 2; targetReg = code[1] & 7;
                }
                if (code[0] == 0x41 && code[1] == 0xFF && iLen >= 3 && (code[2] & 0xF8) == 0xE0) {
                    isJmpReg = true; jmpLen = 3; targetReg = 8 + (code[2] & 7);
                }

                if (isJmpReg && rt.isKnown(targetReg)) {
                    uint32_t target = (uint32_t)rt.regs[targetReg];
                    if (target > 0 && target < soi) {
                        results.push_back({instrRVA, target, jmpLen});
                    }
                    break;
                }

                if (isJmpReg) break;
                if (code[0] == 0xC3 || code[0] == 0xCB) break;
                if (code[0] == 0xE9) break;
                if (code[0] == 0xEB) break;
                if (code[0] == 0xCC) break;

                trackInstr(rt, code, iLen, instrRVA);
                pos += iLen;
            }
        }

        for (uint32_t pos = 7; pos + 2 < rawSz; pos++) {
            uint32_t off = rawOff + pos;
            uint8_t b0 = pe.data[off], b1 = pe.data[off + 1];

            bool isJmpReg = false;
            uint8_t jmpLen = 0;
            int targetReg = -1;

            if (b0 == 0xFF && (b1 & 0xF8) == 0xE0) {
                isJmpReg = true; jmpLen = 2; targetReg = b1 & 7;
            }
            if (pos > 0 && pe.data[off - 1] == 0x41 && b0 == 0xFF && (b1 & 0xF8) == 0xE0) continue;
            if (b0 == 0x41 && b1 == 0xFF && pos + 3 < rawSz && (pe.data[off + 2] & 0xF8) == 0xE0) {
                isJmpReg = true; jmpLen = 3; targetReg = 8 + (pe.data[off + 2] & 7);
            }
            if (!isJmpReg) continue;

            uint32_t jmpRVA = secRVA + pos;
            bool already = false;
            for (auto& r : results) if (r.jmpRVA == jmpRVA) { already = true; break; }
            if (already) continue;

            for (int back = 7; back < 100; back++) {
                if (pos < (uint32_t)back) break;
                uint32_t scanRVA = secRVA + pos - back;
                if (funcSet.count(scanRVA) && back > 7) break;
                uint32_t scanOff = rawOff + pos - back;
                uint8_t s0 = pe.data[scanOff], s1 = pe.data[scanOff + 1], s2 = pe.data[scanOff + 2];

                if ((s0 == 0x48 || s0 == 0x4C) && s1 == 0x8D && (s2 & 0xC7) == 0x05) {
                    int leaReg = (s2 >> 3) & 7;
                    if (s0 == 0x4C) leaReg += 8;
                    if (leaReg == targetReg) {
                        int32_t disp = *(int32_t*)(pe.data.data() + scanOff + 3);
                        uint32_t target = scanRVA + 7 + disp;
                        if (target > 0 && target < soi) {
                            results.push_back({jmpRVA, target, jmpLen});
                        }
                        break;
                    }
                }
            }
        }
    }

    return results;
}

JmpResStats patchIndirectJumps(PEFile& pe, uint64_t imageBase,
    const std::vector<ResolvedJmp>& resolved) {

    (void)imageBase;
    JmpResStats stats = {};
    stats.resolved = (uint32_t)resolved.size();

    for (auto& rj : resolved) {
        uint32_t off = pe.rvaToOffset(rj.jmpRVA);
        if (!off || off + 5 > pe.data.size()) continue;

        uint32_t available = rj.jmpLen;
        while (available < 5 && off + available < pe.data.size()) {
            uint8_t b = pe.data[off + available];
            if (b == 0x90 || b == 0xCC || b == 0x00) { available++; continue; }
            break;
        }

        uint32_t backExt = 0;
        if (available < 5) {
            while (backExt < 5 && off > backExt + 1) {
                uint8_t prev = pe.data[off - backExt - 1];
                if (prev == 0x90 || prev == 0xCC) backExt++;
                else break;
            }
        }

        uint32_t totalSpace = backExt + available;
        if (totalSpace < 5) {
            int32_t shortDisp = (int32_t)(rj.targetRVA - (rj.jmpRVA + 2));
            if (shortDisp >= -128 && shortDisp <= 127 && rj.jmpLen >= 2) {
                pe.data[off] = 0xEB;
                pe.data[off + 1] = (uint8_t)(int8_t)shortDisp;
                for (uint32_t n = 2; n < rj.jmpLen; n++) pe.data[off + n] = 0x90;
                stats.patched++;
                continue;
            }
            continue;
        }

        uint32_t patchOff = off - backExt;
        uint32_t patchRVA = rj.jmpRVA - backExt;

        int32_t disp = (int32_t)(rj.targetRVA - (patchRVA + 5));
        pe.data[patchOff] = 0xE9;
        memcpy(pe.data.data() + patchOff + 1, &disp, 4);
        for (uint32_t n = 5; n < totalSpace; n++)
            pe.data[patchOff + n] = 0x90;

        stats.patched++;
    }

    stats.totalIndirect = stats.resolved;
    return stats;
}

std::vector<ResolvedIndirectCall> resolveIndirectCalls(
    const PEFile& pe, uint64_t imageBase) {

    std::vector<ResolvedIndirectCall> results;
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    std::unordered_set<int> iatSections;
    for (int si = 0; si < pe.numSections; si++) {
        char sn[9] = {};
        memcpy(sn, pe.sections[si].Name, 8);
        if (strncmp(sn, ".idata", 6) == 0)
            iatSections.insert(si);
    }

    auto& impDir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    uint32_t iatStart = impDir.VirtualAddress;
    uint32_t iatEnd = iatStart + impDir.Size;

    for (int si = 0; si < pe.numSections; si++) {
        if (!(pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t secRVA = pe.sections[si].VirtualAddress;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;

        for (uint32_t p = 0; p + 6 <= rawSz; p++) {
            const uint8_t* b = pe.data.data() + rawOff + p;

            if (b[0] != 0xFF) continue;
            bool isCall = (b[1] == 0x15);
            bool isJmp = (b[1] == 0x25);
            if (!isCall && !isJmp) continue;

            uint32_t instrRVA = secRVA + p;
            int32_t disp = *(int32_t*)(b + 2);
            uint32_t nextRVA = instrRVA + 6;
            uint32_t pointerRVA = nextRVA + disp;

            if (pointerRVA >= soi) continue;
            uint32_t ptrOff = pe.rvaToOffset(pointerRVA);
            if (!ptrOff || ptrOff + 8 > pe.data.size()) continue;

            if (pointerRVA >= iatStart && pointerRVA < iatEnd) continue;
            int ptrSec = pe.findSection(pointerRVA);
            if (ptrSec >= 0 && iatSections.count(ptrSec)) continue;

            uint64_t targetVA = *(uint64_t*)(pe.data.data() + ptrOff);
            if (targetVA < imageBase || targetVA >= imageBase + soi) continue;
            uint32_t targetRVA = (uint32_t)(targetVA - imageBase);

            int targetSec = pe.findSection(targetRVA);
            if (targetSec < 0 || !(pe.sections[targetSec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            uint32_t targetOff = pe.rvaToOffset(targetRVA);
            if (!targetOff) continue;
            uint8_t firstByte = pe.data[targetOff];
            if (firstByte == 0x00 || firstByte == 0xCC) continue;

            results.push_back({instrRVA, pointerRVA, targetRVA, isCall});
        }
    }

    return results;
}

IndirectCallStats patchIndirectCalls(PEFile& pe, uint64_t imageBase,
    const std::vector<ResolvedIndirectCall>& resolved) {

    (void)imageBase;
    IndirectCallStats stats = {};
    stats.totalScanned = (uint32_t)resolved.size();
    stats.resolved = (uint32_t)resolved.size();

    for (auto& rc : resolved) {
        uint32_t off = pe.rvaToOffset(rc.instrRVA);
        if (!off || off + 6 > pe.data.size()) continue;

        int32_t relDisp = (int32_t)(rc.targetRVA - (rc.instrRVA + 5));
        pe.data[off] = rc.isCall ? 0xE8 : 0xE9;
        memcpy(pe.data.data() + off + 1, &relDisp, 4);
        pe.data[off + 5] = 0x90;

        stats.patched++;
    }

    return stats;
}

} // namespace griffin
