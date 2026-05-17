#include <griffin/griffin.h>
#include <griffin/mba.h>
#include <pefix/pe.h>
#include <algorithm>

using pefix::Op;
using pefix::Reg;
using pefix::Width;
using pefix::Instr;
using pefix::Block;
using pefix::Func;
using pefix::Value;
using pefix::CC;
using pefix::AbstractValue;

namespace griffin {

bool ConstProp::transferUnknown(const Instr& instr) {
    AbstractValue s1 = getVal(instr.src1);
    AbstractValue s2 = getVal(instr.src2);

    auto fold = [&](uint64_t v) {
        setVal(instr.dst, AbstractValue::MkConst(v, instr.dst.width));
    };

    switch (instr.op) {
    case MBA_XOR:
        if (s1.isConst() && s2.isConst()) fold(s1.masked() ^ s2.masked());
        else setVal(instr.dst, AbstractValue::Top());
        return true;
    case MBA_OR:
        if (s1.isConst() && s2.isConst()) fold(s1.masked() | s2.masked());
        else setVal(instr.dst, AbstractValue::Top());
        return true;
    case MBA_AND:
        if (s1.isConst() && s2.isConst()) fold(s1.masked() & s2.masked());
        else setVal(instr.dst, AbstractValue::Top());
        return true;
    case MBA_ADD:
        if (s1.isConst() && s2.isConst()) fold(s1.masked() + s2.masked());
        else setVal(instr.dst, AbstractValue::Top());
        return true;
    case MBA_SUB:
        if (s1.isConst() && s2.isConst()) fold(s1.masked() - s2.masked());
        else setVal(instr.dst, AbstractValue::Top());
        return true;
    }
    return false;
}

static bool sameReg(const Value& a, const Value& b) {
    return a.isReg() && b.isReg() && a.reg == b.reg;
}

static int findLastDef(const Block& blk, int before, Reg reg) {
    for (int i = before - 1; i >= 0; i--) {
        if (blk.instrs[i].dead) continue;
        if (blk.instrs[i].dst.isReg() && blk.instrs[i].dst.reg == reg)
            return i;
    }
    return -1;
}

bool MBA::matchOR(Block& blk, int start) {
    auto& i0 = blk.instrs[start];
    if (i0.op != Op::NOT || !i0.dst.isReg()) return false;

    int andIdx = findLastDef(blk, start, i0.src1.reg);
    if (andIdx < 0) return false;
    auto& iAnd = blk.instrs[andIdx];
    if (iAnd.op != Op::AND) return false;

    int notAIdx = findLastDef(blk, andIdx, iAnd.src1.reg);
    int notBIdx = findLastDef(blk, andIdx, iAnd.src2.reg);
    if (notAIdx < 0 || notBIdx < 0) return false;

    auto& iNotA = blk.instrs[notAIdx];
    auto& iNotB = blk.instrs[notBIdx];
    if (iNotA.op != Op::NOT || iNotB.op != Op::NOT) return false;

    i0.op = griffin::MBA_OR;
    i0.src1 = iNotA.src1;
    i0.src2 = iNotB.src1;
    i0.simplified = true;
    iAnd.dead = true;
    iNotA.dead = true;
    iNotB.dead = true;
    return true;
}

bool MBA::matchOrAndXor(Block& blk, int start) {
    auto& i0 = blk.instrs[start];
    if (i0.op != Op::AND || !i0.dst.isReg()) return false;

    int orLIdx = findLastDef(blk, start, i0.src1.reg);
    int orRIdx = findLastDef(blk, start, i0.src2.reg);
    if (orLIdx < 0 || orRIdx < 0) return false;

    auto& iOrL = blk.instrs[orLIdx];
    auto& iOrR = blk.instrs[orRIdx];
    if (iOrL.op != Op::OR || iOrR.op != Op::OR) return false;

    auto checkNotOf = [&](Reg reg, int before) -> int {
        int notIdx = findLastDef(blk, before, reg);
        if (notIdx < 0) return -1;
        if (blk.instrs[notIdx].op == Op::NOT) return notIdx;
        return -1;
    };

    int notL1 = checkNotOf(iOrR.src1.reg, orRIdx);
    int notL2 = checkNotOf(iOrR.src2.reg, orRIdx);
    if (notL1 >= 0 && notL2 >= 0) {
        auto& nL1 = blk.instrs[notL1];
        auto& nL2 = blk.instrs[notL2];
        if (sameReg(nL1.src1, iOrL.src1) && sameReg(nL2.src1, iOrL.src2)) {
            i0.op = griffin::MBA_XOR;
            i0.src1 = iOrL.src1;
            i0.src2 = iOrL.src2;
            i0.simplified = true;
            iOrL.dead = true; iOrR.dead = true;
            nL1.dead = true; nL2.dead = true;
            return true;
        }
        if (sameReg(nL1.src1, iOrL.src2) && sameReg(nL2.src1, iOrL.src1)) {
            i0.op = griffin::MBA_XOR;
            i0.src1 = iOrL.src1;
            i0.src2 = iOrL.src2;
            i0.simplified = true;
            iOrL.dead = true; iOrR.dead = true;
            nL1.dead = true; nL2.dead = true;
            return true;
        }
    }

    notL1 = checkNotOf(iOrL.src1.reg, orLIdx);
    notL2 = checkNotOf(iOrL.src2.reg, orLIdx);
    if (notL1 >= 0 && notL2 >= 0) {
        auto& nL1 = blk.instrs[notL1];
        auto& nL2 = blk.instrs[notL2];
        if (sameReg(nL1.src1, iOrR.src1) && sameReg(nL2.src1, iOrR.src2)) {
            i0.op = griffin::MBA_XOR;
            i0.src1 = iOrR.src1;
            i0.src2 = iOrR.src2;
            i0.simplified = true;
            iOrL.dead = true; iOrR.dead = true;
            nL1.dead = true; nL2.dead = true;
            return true;
        }
    }

    return false;
}

bool MBA::matchDoubleNOT(Block& blk, int start) {
    auto& i0 = blk.instrs[start];
    if (i0.op != Op::NOT || !i0.dst.isReg()) return false;

    int innerIdx = findLastDef(blk, start, i0.src1.reg);
    if (innerIdx < 0) return false;
    auto& inner = blk.instrs[innerIdx];
    if (inner.op != Op::NOT) return false;

    i0.op = Op::MOV;
    i0.src1 = inner.src1;
    i0.simplified = true;
    inner.dead = true;
    return true;
}

bool MBA::matchXOR(Block& blk, int start) {
    auto& i0 = blk.instrs[start];
    if (i0.op != Op::NOT || !i0.dst.isReg()) return false;

    int andTopIdx = findLastDef(blk, start, i0.src1.reg);
    if (andTopIdx < 0) return false;
    auto& iAndTop = blk.instrs[andTopIdx];
    if (iAndTop.op != Op::AND) return false;

    int notLIdx = findLastDef(blk, andTopIdx, iAndTop.src1.reg);
    int notRIdx = findLastDef(blk, andTopIdx, iAndTop.src2.reg);
    if (notLIdx < 0 || notRIdx < 0) return false;

    auto& iNotL = blk.instrs[notLIdx];
    auto& iNotR = blk.instrs[notRIdx];
    if (iNotL.op != Op::NOT || iNotR.op != Op::NOT) return false;

    int andLIdx = findLastDef(blk, notLIdx, iNotL.src1.reg);
    int andRIdx = findLastDef(blk, notRIdx, iNotR.src1.reg);
    if (andLIdx < 0 || andRIdx < 0) return false;

    auto& iAndL = blk.instrs[andLIdx];
    auto& iAndR = blk.instrs[andRIdx];
    if (iAndL.op != Op::AND || iAndR.op != Op::AND) return false;

    auto tryMatch = [&](const Instr& andInstr, int andI, Value& pDirect, Value& pNotted) -> bool {
        int n1 = findLastDef(blk, andI, andInstr.src1.reg);
        if (n1 >= 0 && blk.instrs[n1].op == Op::NOT) {
            pDirect = andInstr.src2;
            pNotted = blk.instrs[n1].src1;
            blk.instrs[n1].dead = true;
            return true;
        }
        int n2 = findLastDef(blk, andI, andInstr.src2.reg);
        if (n2 >= 0 && blk.instrs[n2].op == Op::NOT) {
            pDirect = andInstr.src1;
            pNotted = blk.instrs[n2].src1;
            blk.instrs[n2].dead = true;
            return true;
        }
        return false;
    };

    Value directL, nottedL, directR, nottedR;
    if (tryMatch(iAndL, andLIdx, directL, nottedL) && tryMatch(iAndR, andRIdx, directR, nottedR)) {
        i0.op = griffin::MBA_XOR;
        i0.src1 = directL;
        i0.src2 = nottedL;
        i0.simplified = true;
        iAndTop.dead = true;
        iNotL.dead = true;
        iNotR.dead = true;
        iAndL.dead = true;
        iAndR.dead = true;
        return true;
    }

    return false;
}

bool MBA::matchTestZero(Block& blk, int start) {
    auto& instr = blk.instrs[start];
    if (instr.op != Op::TEST) return false;
    if (instr.src2.isImm() && instr.src2.imm == 0) {
        instr.simplified = true;
        for (int j = start + 1; j < (int)blk.instrs.size(); j++) {
            auto& next = blk.instrs[j];
            if (next.dead) continue;
            if (next.flagsWritten) break;
            if (next.op == Op::JCC) {
                if (next.cc == CC::Z) {
                    next.op = Op::JMP;
                    next.cc = CC::NONE;
                    next.simplified = true;
                } else if (next.cc == CC::NZ) {
                    next.dead = true;
                }
            }
            if (next.op == Op::CMOV) {
                if (next.cc == CC::Z) {
                    next.op = Op::MOV;
                    next.cc = CC::NONE;
                    next.simplified = true;
                } else if (next.cc == CC::NZ) {
                    next.dead = true;
                }
            }
        }
        return true;
    }
    return false;
}

void MBA::eliminateDeadCode(Block& blk) {
    (void)blk;
}

int MBA::eliminateDeadPaths(Block& blk) {
    int eliminated = 0;

    for (int i = 0; i < (int)blk.instrs.size(); i++) {
        auto& instr = blk.instrs[i];
        if (instr.dead) continue;

        if (instr.op == Op::JMP && instr.simplified && instr.dst.kind == Value::LABEL) {
            uint64_t targetAddr = (uint64_t)instr.dst.imm;

            for (int j = i + 1; j < (int)blk.instrs.size(); j++) {
                if (blk.instrs[j].dead) continue;
                if (blk.instrs[j].addr == targetAddr) break;

                bool isJumpTarget = false;
                for (int k = 0; k < (int)blk.instrs.size(); k++) {
                    if (k == i || blk.instrs[k].dead) continue;
                    if ((blk.instrs[k].op == Op::JMP || blk.instrs[k].op == Op::JCC) &&
                        blk.instrs[k].dst.kind == Value::LABEL &&
                        (uint64_t)blk.instrs[k].dst.imm == blk.instrs[j].addr) {
                        isJumpTarget = true;
                        break;
                    }
                }
                if (isJumpTarget) break;

                blk.instrs[j].dead = true;
                eliminated++;
            }
        }
    }

    return eliminated;
}

static bool hasSideEffect(const Instr& instr) {
    switch (instr.op) {
    case Op::STORE: case Op::PUSH:
    case Op::CALL: case Op::RET:
    case Op::JMP: case Op::JCC:
    case Op::INT3: case Op::UD2:
    case Op::CMP: case Op::TEST: case Op::BT:
        return true;
    default:
        return false;
    }
}

static void getUsedRegs(const Instr& instr, uint16_t used[], int& count) {
    count = 0;
    if (instr.src1.isReg() && (uint16_t)instr.src1.reg < 16)
        used[count++] = (uint16_t)instr.src1.reg;
    if (instr.src2.isReg() && (uint16_t)instr.src2.reg < 16)
        used[count++] = (uint16_t)instr.src2.reg;
    if (instr.src1.isMem()) {
        if (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
            used[count++] = (uint16_t)instr.src1.reg;
        if (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
            used[count++] = (uint16_t)instr.src1.index;
    }
    if (instr.op == Op::STORE && instr.dst.isMem()) {
        if (instr.dst.reg != Reg::NONE && (uint16_t)instr.dst.reg < 16)
            used[count++] = (uint16_t)instr.dst.reg;
        if (instr.dst.index != Reg::NONE && (uint16_t)instr.dst.index < 16)
            used[count++] = (uint16_t)instr.dst.index;
    }
}

int MBA::livenessDCE(GriffinFunc& func) {
    int totalKilled = 0;

    for (auto& blk : func.blocks) {
        if (blk.isDeadCode) continue;

        bool changed = true;
        while (changed) {
            changed = false;

            for (int i = (int)blk.instrs.size() - 1; i >= 0; i--) {
                auto& instr = blk.instrs[i];
                if (instr.dead) continue;
                if (hasSideEffect(instr)) continue;
                if (!instr.dst.isReg()) continue;

                uint16_t dstReg = (uint16_t)instr.dst.reg;
                if (dstReg >= 16) continue;
                if (dstReg == (uint16_t)Reg::RSP) continue;

                bool isUsed = false;
                bool isRedefined = false;
                for (int j = i + 1; j < (int)blk.instrs.size(); j++) {
                    auto& later = blk.instrs[j];
                    if (later.dead) continue;

                    uint16_t used[6]; int cnt;
                    getUsedRegs(later, used, cnt);
                    for (int k = 0; k < cnt; k++) {
                        if (used[k] == dstReg) { isUsed = true; break; }
                    }
                    if (isUsed) break;

                    if (later.dst.isReg() && (uint16_t)later.dst.reg == dstReg) {
                        isRedefined = true;
                        break;
                    }
                }

                if (!isUsed && isRedefined) {
                    instr.dead = true;
                    changed = true;
                    totalKilled++;
                }
            }
        }
    }

    return totalKilled;
}

bool MBA::simplifyBlock(Block& blk) {
    bool any = false;
    for (int pass = 0; pass < 4; pass++) {
        bool changed = false;
        for (int i = (int)blk.instrs.size() - 1; i >= 0; i--) {
            if (blk.instrs[i].dead) continue;
            if (matchXOR(blk, i)) { changed = true; continue; }
            if (matchOrAndXor(blk, i)) { changed = true; continue; }
            if (matchOR(blk, i)) { changed = true; continue; }
            if (matchDoubleNOT(blk, i)) { changed = true; continue; }
            if (matchTestZero(blk, i)) { changed = true; continue; }
        }
        if (changed) any = true;
        else break;
    }
    return any;
}

void MBA::run(GriffinFunc& func) {
    for (auto& blk : func.blocks) {
        if (blk.isDeadCode) continue;
        simplifyBlock(blk);
    }
}

} // namespace griffin
