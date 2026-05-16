#include <griffin/griffin.h>
#include <griffin/mba.h>
#include <pefix/pe.h>
#include <queue>
#include <cstdio>
#include <algorithm>

using pefix::Op;
using pefix::Reg;
using pefix::Width;
using pefix::Instr;
using pefix::Block;
using pefix::Func;
using pefix::Value;

namespace griffin {

// Bring griffin extended ops into Op-compatible scope
static constexpr auto MBA_XOR_OP = griffin::MBA_XOR;
static constexpr auto MBA_OR_OP = griffin::MBA_OR;
static constexpr auto MBA_AND_OP = griffin::MBA_AND;
static constexpr auto MBA_ADD_OP = griffin::MBA_ADD;
static constexpr auto MBA_SUB_OP = griffin::MBA_SUB;

using namespace pefix;

void ConstProp::initState() {
    for (int i = 0; i < 16; i++) regs_[i] = AbstractValue::Top();
    for (int i = 0; i < 5; i++) flags_[i] = AbstractValue::Top();
    regs_[(int)Reg::RSP] = AbstractValue::MkConst(0, Width::W64);
}

AbstractValue ConstProp::getVal(const Value& v) {
    if (v.kind == Value::IMM) return AbstractValue::MkConst((uint64_t)v.imm, v.width);
    if (v.kind == Value::REG && (uint16_t)v.reg < 16)
        return regs_[(uint16_t)v.reg];
    return AbstractValue::Top();
}

void ConstProp::setVal(const Value& v, AbstractValue av) {
    if (v.kind == Value::REG && (uint16_t)v.reg < 16) {
        if (!av.isConst() && dispatchKeyRegs_.count((uint16_t)v.reg)) return;
        av.width = v.width;
        if (v.width == Width::W32) av.value &= 0xFFFFFFFF;
        else if (v.width == Width::W16) av.value &= 0xFFFF;
        else if (v.width == Width::W8) av.value &= 0xFF;
        regs_[(uint16_t)v.reg] = av;
    }
}

void ConstProp::transfer(const Instr& instr) {
    if (instr.dead) return;

    AbstractValue s1 = getVal(instr.src1);
    AbstractValue s2 = getVal(instr.src2);

    switch (instr.op) {
    case Op::MOV:
        if (instr.dst.isReg() && instr.src1.isMem()) {
            AbstractValue base = (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
                ? regs_[(uint16_t)instr.src1.reg] : AbstractValue::Top();
            if (base.isTypedPtr() && instr.src1.index == Reg::NONE && imageBase_ > 0) {
                int32_t fieldOff = (int32_t)instr.src1.imm;
                if (fieldOff == 0) {
                    setVal(instr.dst, AbstractValue::MkConst(imageBase_ + base.value, Width::W64));
                    break;
                }
                if (fieldTypes_ && fieldOff > 0) {
                    uint64_t key = ((uint64_t)base.value << 32) | (uint32_t)fieldOff;
                    auto fit = fieldTypes_->find(key);
                    if (fit != fieldTypes_->end()) {
                        setVal(instr.dst, AbstractValue::MkTypedPtr(fit->second));
                        break;
                    }
                }
                if (fieldOff > 0 && fieldOff < 0x200) {
                    setVal(instr.dst, AbstractValue::MkTypedPtr((uint32_t)base.value));
                    break;
                }
            }
            if (instr.src1.reg == Reg::RIP) {
                uint64_t addr = (uint64_t)instr.src1.imm;
                if (pe_ && addr > 0) {
                    uint32_t rva = (uint32_t)(addr & 0xFFFFFFFF);
                    uint32_t off = pe_->rvaToOffset(rva);
                    if (off && off + 8 <= pe_->data.size()) {
                        int sec = pe_->findSection(rva);
                        if (sec >= 0 && !(pe_->sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                            uint64_t val = *(uint64_t*)(pe_->data.data() + off);
                            setVal(instr.dst, AbstractValue::MkConst(val, instr.dst.width));
                            break;
                        }
                    }
                }
            } else if (base.isConst() || (instr.src1.reg == Reg::NONE && instr.src1.index != Reg::NONE)) {
                AbstractValue idx = (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
                    ? regs_[(uint16_t)instr.src1.index] : AbstractValue::Top();
                bool canCompute = true;
                uint64_t addr = instr.src1.imm;
                if (instr.src1.reg != Reg::NONE) {
                    if (base.isConst()) addr += base.value;
                    else canCompute = false;
                }
                if (instr.src1.index != Reg::NONE) {
                    if (idx.isConst()) addr += idx.value * (instr.src1.scale ? instr.src1.scale : 1);
                    else canCompute = false;
                }
                if (canCompute && pe_ && addr > 0) {
                    uint32_t rva = (addr >= imageBase_) ? (uint32_t)(addr - imageBase_) : (uint32_t)(addr & 0xFFFFFFFF);
                    uint32_t off = pe_->rvaToOffset(rva);
                    if (off && off + 8 <= pe_->data.size()) {
                        int sec = pe_->findSection(rva);
                        if (sec >= 0 && !(pe_->sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                            uint64_t val = *(uint64_t*)(pe_->data.data() + off);
                            setVal(instr.dst, AbstractValue::MkConst(val, instr.dst.width));
                            break;
                        }
                    }
                }
            }
            setVal(instr.dst, AbstractValue::Top());
        } else {
            setVal(instr.dst, s1);
        }
        break;
    case Op::LEA:
        if (instr.src1.isMem()) {
            AbstractValue base = (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
                ? regs_[(uint16_t)instr.src1.reg] : AbstractValue::Top();
            AbstractValue idx = (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
                ? regs_[(uint16_t)instr.src1.index] : AbstractValue::Top();
            if (base.isConst() && (instr.src1.index == Reg::NONE || idx.isConst())) {
                uint64_t result = base.value + instr.src1.imm;
                if (instr.src1.index != Reg::NONE)
                    result += idx.value * (instr.src1.scale ? instr.src1.scale : 1);
                setVal(instr.dst, AbstractValue::MkConst(result, instr.dst.width));
            } else {
                setVal(instr.dst, AbstractValue::Top());
            }
        }
        break;
    case Op::ADD:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() + s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SUB:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() - s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::IMUL:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() * s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::AND:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() & s2.masked(), instr.dst.width));
        else if (s2.isConst() && s2.value == 0)
            setVal(instr.dst, AbstractValue::MkConst(0, instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::OR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() | s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::XOR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() ^ s2.masked(), instr.dst.width));
        else if (instr.src1.isReg() && instr.src2.isReg() && instr.src1.reg == instr.src2.reg)
            setVal(instr.dst, AbstractValue::MkConst(0, instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::NOT:
        if (s1.isConst())
            setVal(instr.dst, AbstractValue::MkConst(~s1.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SHL:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() << (s2.value & 63), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SHR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() >> (s2.value & 63), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SAR:
        if (s1.isConst() && s2.isConst()) {
            int64_t sv = (int64_t)s1.masked();
            setVal(instr.dst, AbstractValue::MkConst((uint64_t)(sv >> (s2.value & 63)), instr.dst.width));
        } else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::TEST:
        if (s1.isConst() && s2.isConst()) {
            uint64_t result = s1.masked() & s2.masked();
            setFlag(0, AbstractValue::MkConst(result == 0 ? 1 : 0));
            setFlag(1, AbstractValue::MkConst(0));
            setFlag(2, AbstractValue::MkConst((result >> 63) & 1));
            setFlag(3, AbstractValue::MkConst(0));
        } else {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    case Op::CMP:
        if (s1.isConst() && s2.isConst()) {
            uint64_t a = s1.masked(), b = s2.masked();
            setFlag(0, AbstractValue::MkConst(a == b ? 1 : 0));
            setFlag(1, AbstractValue::MkConst(a < b ? 1 : 0));
            int64_t sa = (int64_t)a, sb = (int64_t)b;
            setFlag(2, AbstractValue::MkConst(((sa - sb) < 0) ? 1 : 0));
        } else {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    case Op::BT:
        if (s1.isConst() && s2.isConst()) {
            uint64_t bit = (s1.masked() >> (s2.value & 63)) & 1;
            setFlag(1, AbstractValue::MkConst(bit));
        } else {
            setFlag(1, AbstractValue::Top());
        }
        break;
    case griffin::MBA_XOR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() ^ s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case griffin::MBA_OR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() | s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case griffin::MBA_AND:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() & s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case griffin::MBA_ADD:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() + s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case griffin::MBA_SUB:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() - s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::CALL: {
        regs_[(int)Reg::RAX] = AbstractValue::Top();
        regs_[(int)Reg::RCX] = AbstractValue::Top();
        regs_[(int)Reg::RDX] = AbstractValue::Top();
        regs_[(int)Reg::R8]  = AbstractValue::Top();
        regs_[(int)Reg::R9]  = AbstractValue::Top();
        regs_[(int)Reg::R10] = AbstractValue::Top();
        regs_[(int)Reg::R11] = AbstractValue::Top();
        for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        if (returnTypes_ && instr.dst.kind == Value::LABEL && instr.dst.imm > 0) {
            uint32_t calleeRVA = (uint32_t)(instr.dst.imm & 0xFFFFFFFF);
            auto rit = returnTypes_->find(calleeRVA);
            if (rit != returnTypes_->end()) {
                regs_[(int)Reg::RAX] = AbstractValue::MkTypedPtr(rit->second);
            }
        }
        break;
    }
    default:
        if (!instr.dst.isNone()) setVal(instr.dst, AbstractValue::Top());
        if (instr.flagsWritten) {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    }
}

int ConstProp::evalCCResult(CC cc) {
    AbstractValue zf = getFlag(0), cf = getFlag(1), sf = getFlag(2), of = getFlag(3);
    switch (cc) {
    case CC::Z:  return zf.isConst() ? (int)(zf.value & 1) : -1;
    case CC::NZ: return zf.isConst() ? (int)(1 - (zf.value & 1)) : -1;
    case CC::B:  return cf.isConst() ? (int)(cf.value & 1) : -1;
    case CC::AE: return cf.isConst() ? (int)(1 - (cf.value & 1)) : -1;
    case CC::S:  return sf.isConst() ? (int)(sf.value & 1) : -1;
    case CC::NS: return sf.isConst() ? (int)(1 - (sf.value & 1)) : -1;
    case CC::BE: return (cf.isConst() && zf.isConst()) ? (int)((cf.value | zf.value) & 1) : -1;
    case CC::A:  return (cf.isConst() && zf.isConst()) ? (int)(1 - ((cf.value | zf.value) & 1)) : -1;
    case CC::L:  return (sf.isConst() && of.isConst()) ? (int)((sf.value != of.value) ? 1 : 0) : -1;
    case CC::GE: return (sf.isConst() && of.isConst()) ? (int)((sf.value == of.value) ? 1 : 0) : -1;
    default: return -1;
    }
}

void ConstProp::run(GriffinFunc& func) {
    dispatchKeyRegs_.clear();
    auto& blocks = func.blocks;
    size_t numBlocks = blocks.size();
    if (numBlocks == 0) return;

    struct BlockState {
        AbstractValue regs[16];
        AbstractValue flags[5];
        bool reached = false;
    };
    std::vector<BlockState> blockStates(numBlocks);

    for (int r = 0; r < 16; r++) blockStates[0].regs[r] = AbstractValue::Top();
    for (int f = 0; f < 5; f++) blockStates[0].flags[f] = AbstractValue::Top();
    blockStates[0].regs[(int)Reg::RSP] = AbstractValue::MkConst(0, Width::W64);
    for (auto& [reg, val] : initRegs_) {
        if (reg < 16) blockStates[0].regs[reg] = AbstractValue::MkConst(val, Width::W64);
    }
    for (auto& [reg, vtRVA] : typedPtrs_) {
        if (reg < 16) blockStates[0].regs[reg] = AbstractValue::MkTypedPtr(vtRVA);
    }
    for (auto& dk : func.dispatchKeys) {
        if (dk.reg != Reg::NONE && (uint16_t)dk.reg < 16) {
            blockStates[0].regs[(uint16_t)dk.reg] = AbstractValue::MkConst((uint64_t)dk.value, Width::W32);
            dispatchKeyRegs_.insert((uint16_t)dk.reg);
        }
    }
    if (func.dispatchKeys.empty() && func.dispatchKeyValue != INT64_MIN && func.dispatchKeyReg != Reg::NONE) {
        blockStates[0].regs[(uint16_t)func.dispatchKeyReg] =
            AbstractValue::MkConst((uint64_t)func.dispatchKeyValue, Width::W32);
        dispatchKeyRegs_.insert((uint16_t)func.dispatchKeyReg);
    }
    blockStates[0].reached = true;

    std::vector<bool> inWorklist(numBlocks, false);
    std::queue<uint32_t> worklist;
    worklist.push(0);
    inWorklist[0] = true;

    int iterations = 0;
    while (!worklist.empty() && iterations < (int)numBlocks * 3) {
        uint32_t bi = worklist.front(); worklist.pop(); inWorklist[bi] = false;
        auto& blk = blocks[bi];
        if (blk.isDeadCode) continue;
        iterations++;

        for (int r = 0; r < 16; r++) regs_[r] = blockStates[bi].regs[r];
        for (int f = 0; f < 5; f++) flags_[f] = blockStates[bi].flags[f];

        for (auto& dk : func.dispatchKeys)
            if (dk.reg != Reg::NONE && (uint16_t)dk.reg < 16)
                regs_[(uint16_t)dk.reg] = AbstractValue::MkConst((uint64_t)dk.value, Width::W32);

        for (auto& instr : blk.instrs) {
            if (instr.dead) continue;

            if (instr.op == Op::JCC) {
                int r = evalCCResult(instr.cc);
                if (r == 1) {
                    const_cast<Instr&>(instr).op = Op::JMP;
                    const_cast<Instr&>(instr).cc = CC::NONE;
                    const_cast<Instr&>(instr).simplified = true;
                } else if (r == 0) {
                    const_cast<Instr&>(instr).op = Op::NOP;
                    const_cast<Instr&>(instr).simplified = true;
                }
            }

            if (instr.op == Op::CMOV) {
                int r = evalCCResult(instr.cc);
                if (r == 1) {
                    const_cast<Instr&>(instr).op = Op::MOV;
                    const_cast<Instr&>(instr).cc = CC::NONE;
                    const_cast<Instr&>(instr).simplified = true;
                } else if (r == 0) {
                    const_cast<Instr&>(instr).dead = true;
                }
            }

            if (instr.op == Op::IMUL && instr.src2.isImm()) {
                AbstractValue sv = getVal(instr.src1);
                if (sv.isConst()) {
                    uint64_t result = sv.masked() * (uint64_t)instr.src2.imm;
                    if (instr.dst.width == Width::W32) result &= 0xFFFFFFFF;
                    const_cast<Instr&>(instr).src1 = Value::Imm((int64_t)result, instr.dst.width);
                    const_cast<Instr&>(instr).src2 = Value::None();
                    const_cast<Instr&>(instr).op = Op::MOV;
                    const_cast<Instr&>(instr).simplified = true;
                }
            }

            transfer(instr);
        }

        for (uint32_t succIdx : blk.succs) {
            if (succIdx >= numBlocks) continue;
            auto& ss = blockStates[succIdx];
            bool changed = false;
            if (!ss.reached) {
                for (int r = 0; r < 16; r++) ss.regs[r] = regs_[r];
                for (int f = 0; f < 5; f++) ss.flags[f] = flags_[f];
                ss.reached = true;
                changed = true;
            } else {
                for (int r = 0; r < 16; r++) {
                    if (ss.regs[r].state == regs_[r].state && ss.regs[r].value == regs_[r].value)
                        continue;
                    if (ss.regs[r].state != AbstractValue::AV_TOP) {
                        ss.regs[r] = AbstractValue::Top();
                        changed = true;
                    }
                }
            }
            if (changed && !inWorklist[succIdx]) {
                worklist.push(succIdx);
                inWorklist[succIdx] = true;
            }
        }
    }
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

    Value origA, origB;

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
