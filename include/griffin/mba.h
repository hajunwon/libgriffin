#pragma once
#include <pefix/constprop.h>
#include <griffin/dispatch.h>
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>

namespace griffin {

using AbstractValue = pefix::AbstractValue;
using GriffinFunc = pefix::Func;

// ConstProp engine extended for MBA-folded ops (MBA_XOR/OR/AND/ADD/SUB) emitted by
// the MBA pattern matchers below. Semantics are identical to plain XOR/OR/AND/ADD/SUB
// but the distinct opcode lets z3solve treat them as recovered folds.
class ConstProp : public pefix::ConstProp {
protected:
    bool transferUnknown(const pefix::Instr& instr) override;
};

class MBA {
public:
    void run(GriffinFunc& func);
    int eliminateDeadPaths(pefix::Block& blk);
    int livenessDCE(GriffinFunc& func);
    bool simplifyBlock(pefix::Block& blk);

private:
    bool matchXOR(pefix::Block& blk, int start);
    bool matchOR(pefix::Block& blk, int start);
    bool matchOrAndXor(pefix::Block& blk, int start);
    bool matchDoubleNOT(pefix::Block& blk, int start);
    bool matchTestZero(pefix::Block& blk, int start);
    void eliminateDeadCode(pefix::Block& blk);
};

} // namespace griffin
