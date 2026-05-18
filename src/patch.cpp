#include <griffin/patch.h>
#include <cstring>
#include <cstdio>

namespace griffin {

using namespace pefix;

static uint32_t vaToOffset(const PEFile& pe, uint64_t imageBase, uint64_t va) {
    if (va < imageBase) return 0;
    uint32_t rva = (uint32_t)(va - imageBase);
    return pe.rvaToOffset(rva);
}

static int encodeMov32Imm(uint8_t* buf, int maxLen, Reg reg, uint32_t imm) {
    uint8_t regIdx = (uint8_t)((uint16_t)reg & 0xF);
    int pos = 0;

    if (regIdx >= 8) {
        if (maxLen < 6) return 0;
        buf[pos++] = 0x41;
        regIdx -= 8;
    } else {
        if (maxLen < 5) return 0;
    }

    buf[pos++] = 0xB8 + regIdx;
    memcpy(buf + pos, &imm, 4);
    pos += 4;
    return pos;
}

static int encodeMovReg(uint8_t* buf, int maxLen, Reg dst, Reg src) {
    if (maxLen < 3) return 0;
    uint8_t d = (uint8_t)((uint16_t)dst & 0xF);
    uint8_t s = (uint8_t)((uint16_t)src & 0xF);

    uint8_t rex = 0x48;
    if (d >= 8) { rex |= 0x04; d -= 8; }
    if (s >= 8) { rex |= 0x01; s -= 8; }

    int pos = 0;
    buf[pos++] = rex;
    buf[pos++] = 0x8B;
    buf[pos++] = 0xC0 | (d << 3) | s;
    return pos;
}

PatchStats applyDeobfPatches(PEFile& pe, uint64_t imageBase, const Func& func) {
    PatchStats stats = {};

    for (auto& blk : func.blocks) {
        if (blk.isDeadCode) continue;

        for (auto& instr : blk.instrs) {
            if (instr.addr == 0 || instr.rawLen == 0) continue;

            uint32_t off = vaToOffset(pe, imageBase, instr.addr);
            if (off == 0 || off + instr.rawLen > pe.data.size()) continue;

            uint8_t* code = pe.data.data() + off;

            if (instr.dead) {
                memset(code, 0x90, instr.rawLen);
                stats.nopsWritten++;
                stats.bytesPatched += instr.rawLen;
                stats.totalPatched++;
                continue;
            }

            if (!instr.simplified) continue;

            if (instr.op == Op::MOV && instr.src1.isImm() && instr.dst.isReg()
                && instr.dst.width == Width::W32) {
                uint32_t imm = (uint32_t)(uint64_t)instr.src1.imm;
                uint8_t enc[6];
                int encLen = encodeMov32Imm(enc, sizeof(enc), instr.dst.reg, imm);
                if (encLen > 0 && encLen <= (int)instr.rawLen) {
                    memcpy(code, enc, encLen);
                    if (encLen < (int)instr.rawLen)
                        memset(code + encLen, 0x90, instr.rawLen - encLen);
                    stats.imulFolded++;
                    stats.bytesPatched += instr.rawLen;
                    stats.totalPatched++;
                }
                continue;
            }

            if (instr.op == Op::MOV && instr.dst.isReg() && instr.src1.isReg()
                && instr.cc == CC::NONE && instr.rawLen >= 3) {
                int rexOff = 0;
                if ((code[0] & 0xF0) == 0x40) rexOff = 1;
                if (rexOff + 2 <= (int)instr.rawLen && code[rexOff] == 0x0F
                    && (code[rexOff + 1] & 0xF0) == 0x40) {
                    uint8_t enc[4];
                    int encLen = encodeMovReg(enc, sizeof(enc), instr.dst.reg, instr.src1.reg);
                    if (encLen > 0 && encLen <= (int)instr.rawLen) {
                        memcpy(code, enc, encLen);
                        if (encLen < (int)instr.rawLen)
                            memset(code + encLen, 0x90, instr.rawLen - encLen);
                        stats.cmovResolved++;
                        stats.bytesPatched += instr.rawLen;
                        stats.totalPatched++;
                    }
                }
                continue;
            }

            if (instr.op == Op::MOV && instr.src1.isImm() && instr.dst.isReg()
                && (uint64_t)instr.src1.imm <= 0xFFFFFFFF && instr.rawLen >= 4) {
                uint32_t imm = (uint32_t)(uint64_t)instr.src1.imm;
                uint8_t enc[6];
                int encLen = encodeMov32Imm(enc, sizeof(enc), instr.dst.reg, imm);
                if (encLen > 0 && encLen <= (int)instr.rawLen) {
                    memcpy(code, enc, encLen);
                    if (encLen < (int)instr.rawLen)
                        memset(code + encLen, 0x90, instr.rawLen - encLen);
                    stats.totalPatched++;
                    stats.bytesPatched += instr.rawLen;
                }
                continue;
            }
        }
    }

    return stats;
}

static bool isObfuscatedSection(const char* name, const std::vector<std::string>& prefixes) {
    for (auto& pfx : prefixes) {
        if (strncmp(name, pfx.c_str(), pfx.size()) == 0)
            return true;
    }
    return false;
}

std::vector<NullsubPatch> patchNullsubs(PEFile& pe,
    const std::vector<std::string>& obfuscatedSections)
{
    const uint8_t pattern[] = { 0xC3, 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
    constexpr size_t PATTERN_LEN = sizeof(pattern);
    std::vector<NullsubPatch> patches;

    // Pass 1: C3 90 E9 00 00 00 00 48 B8 pattern in all executable sections
    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size())
            rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + PATTERN_LEN <= rawSz; pos++) {
            if (memcmp(code + pos, pattern, PATTERN_LEN) != 0) continue;

            bool hasJmpBefore = false;
            if (pos >= 5 && code[pos - 5] == 0xE9)
                hasJmpBefore = true;

            if (hasJmpBefore) {
                code[pos] = 0xCC;
                code[pos + 2] = 0xCC;
                code[pos + 3] = 0xCC;
                code[pos + 4] = 0xCC;
                code[pos + 5] = 0xCC;
                code[pos + 6] = 0xCC;

                NullsubPatch p;
                p.fileOffset = rawOff + pos;
                p.rva = va + pos;
                patches.push_back(p);
            }
        }
    }

    // Pass 2: standalone C3 in obfuscated sections
    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        if (!isObfuscatedSection(name, obfuscatedSections)) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 1; pos + 1 < rawSz; pos++) {
            if (code[pos] != 0xC3) continue;
            uint8_t before = code[pos - 1];
            uint8_t after = code[pos + 1];
            bool deadBefore = (before == 0xCC || before == 0x00 ||
                              (pos >= 5 && code[pos-5] == 0xE9));
            bool deadAfter = (after == 0xCC || after == 0x00 || after == 0x90 ||
                             after == 0xC3 || after == 0xE9);
            if (deadBefore && deadAfter) {
                code[pos] = 0xCC;
                NullsubPatch p;
                p.fileOffset = rawOff + pos;
                p.rva = va + pos;
                patches.push_back(p);
            }
        }
    }

    return patches;
}

static bool isValidInstrByte(uint8_t b) {
    if (b >= 0x40 && b <= 0x4F) return true;
    if (b >= 0x50 && b <= 0x5F) return true;
    if (b >= 0x80 && b <= 0x8F) return true;
    if (b >= 0xB0 && b <= 0xBF) return true;
    switch (b) {
        case 0x0F: case 0x01: case 0x03: case 0x09: case 0x0B:
        case 0x21: case 0x23: case 0x25: case 0x29: case 0x2B: case 0x2D:
        case 0x31: case 0x33: case 0x35: case 0x39: case 0x3B: case 0x3D:
        case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6B:
        case 0xC1: case 0xC6: case 0xC7:
        case 0xD1: case 0xD3:
        case 0xE8: case 0xE9: case 0xEB:
        case 0xF2: case 0xF3: case 0xF6: case 0xF7:
        case 0xFE: case 0xFF:
            return true;
    }
    return false;
}

static bool isBoundaryBefore(uint8_t b) {
    return b == 0xC3 || b == 0x00 || b == 0x90;
}

InlineInt3Stats nopInlineInt3(PEFile& pe, SectionFilter filter) {
    InlineInt3Stats stats = {};

    for (int si = 0; si < pe.numSections; si++) {
        if (!(pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (filter) {
            char name[9] = {};
            memcpy(name, pe.sections[si].Name, 8);
            if (!filter(name)) continue;
        }
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

        // Pass 1: chain detection  - 2+ CC runs with short code gaps between them
        for (uint32_t p = 1; p + 8 < rawSz; p++) {
            if (pe.data[rawOff+p] != 0xCC) continue;
            if (pe.data[rawOff+p-1] == 0xCC) continue;
            if (isBoundaryBefore(pe.data[rawOff + p - 1])) continue;

            uint32_t run1 = 0;
            while (p + run1 < rawSz && pe.data[rawOff+p+run1] == 0xCC) run1++;
            if (run1 < 3 || run1 > 15) continue;

            uint32_t cursor = p + run1;
            if (cursor + 1 >= rawSz) continue;
            if (!isValidInstrByte(pe.data[rawOff + cursor])) continue;

            struct CCRun { uint32_t start; uint32_t len; };
            std::vector<CCRun> runs;
            runs.push_back({p, run1});

            while (cursor + 3 < rawSz) {
                uint32_t codeLen = 0;
                while (cursor + codeLen < rawSz && pe.data[rawOff+cursor+codeLen] != 0xCC) codeLen++;
                if (codeLen < 1 || codeLen > 15) break;

                uint32_t nextCC = cursor + codeLen;
                uint32_t runN = 0;
                while (nextCC + runN < rawSz && pe.data[rawOff+nextCC+runN] == 0xCC) runN++;
                if (runN < 3 || runN > 15) break;

                uint32_t afterN = nextCC + runN;
                if (afterN < rawSz && !isValidInstrByte(pe.data[rawOff + afterN])) break;

                runs.push_back({nextCC, runN});
                cursor = afterN;
            }

            if (runs.size() < 2) continue;

            uint32_t lastEnd = runs.back().start + runs.back().len;
            if (lastEnd >= rawSz) continue;
            if (!isValidInstrByte(pe.data[rawOff + lastEnd])) continue;

            for (auto& r : runs) {
                for (uint32_t k = 0; k < r.len; k++)
                    pe.data[rawOff + r.start + k] = 0x90;
                stats.bytesNoped += r.len;
            }
            p = lastEnd - 1;
        }

        // Pass 2: isolated CC runs bounded by valid code on both sides
        for (uint32_t p = 1; p + 4 < rawSz; p++) {
            if (pe.data[rawOff+p] != 0xCC) continue;
            if (pe.data[rawOff+p-1] == 0xCC) continue;

            uint32_t run = 0;
            while (p + run < rawSz && pe.data[rawOff+p+run] == 0xCC) run++;
            if (run < 3 || run > 15) { p += run - 1; continue; }
            if (pe.data[rawOff+p] == 0x90) { p += run - 1; continue; }
            if (isBoundaryBefore(pe.data[rawOff + p - 1])) { p += run - 1; continue; }
            if (p >= 5 && pe.data[rawOff+p-5] == 0xE9) { p += run - 1; continue; }

            uint32_t after = p + run;
            if (after >= rawSz) { p += run - 1; continue; }
            if (!isValidInstrByte(pe.data[rawOff + after])) { p += run - 1; continue; }

            // REX + CC after = likely function boundary, skip
            if (after + 1 < rawSz) {
                if (pe.data[rawOff + after] >= 0x40 && pe.data[rawOff + after] <= 0x4F &&
                    pe.data[rawOff + after + 1] == 0xCC)
                    { p += run - 1; continue; }
            }

            for (uint32_t k = 0; k < run; k++)
                pe.data[rawOff + p + k] = 0x90;
            stats.bytesNoped += run;
            p += run - 1;
        }
    }

    return stats;
}

} // namespace griffin
