#pragma once
#include <griffin/dispatch.h>
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <set>
#include <unordered_map>

namespace griffin {

struct AbstractValue {
    enum State : uint8_t { AV_TOP, AV_CONST, AV_TYPED_PTR, AV_BOTTOM } state = AV_TOP;
    uint64_t value = 0;
    pefix::Width width = pefix::Width::W64;

    bool isConst() const { return state == AV_CONST; }
    bool isTypedPtr() const { return state == AV_TYPED_PTR; }
    bool isTop() const { return state == AV_TOP; }

    static AbstractValue Top() { return {AV_TOP, 0, pefix::Width::W64}; }
    static AbstractValue MkConst(uint64_t v, pefix::Width w = pefix::Width::W64) { return {AV_CONST, v, w}; }
    static AbstractValue MkTypedPtr(uint32_t vtableRVA) { return {AV_TYPED_PTR, vtableRVA, pefix::Width::W64}; }

    uint64_t masked() const {
        switch (width) {
        case pefix::Width::W8: return value & 0xFF;
        case pefix::Width::W16: return value & 0xFFFF;
        case pefix::Width::W32: return value & 0xFFFFFFFF;
        default: return value;
        }
    }

    AbstractValue meet(const AbstractValue& o) const {
        if (state == AV_TOP) return o;
        if (o.state == AV_TOP) return *this;
        if (state == AV_CONST && o.state == AV_CONST && value == o.value) return *this;
        return {AV_BOTTOM, 0, width};
    }
};

// GriffinFunc wraps Func (which has dispatch key fields built-in)
using GriffinFunc = pefix::Func;

class ConstProp {
public:
    void run(GriffinFunc& func);
    void setPE(const pefix::PEFile* pe, uint64_t imageBase) { pe_ = pe; imageBase_ = imageBase; }
    void setInitReg(pefix::Reg reg, uint64_t val) { initRegs_[(uint16_t)reg] = val; initRegSet_.insert((uint16_t)reg); }
    void setTypedPtr(pefix::Reg reg, uint32_t vtableRVA) { typedPtrs_[(uint16_t)reg] = vtableRVA; }
    void setReturnTypes(const std::unordered_map<uint32_t, uint32_t>* rt) { returnTypes_ = rt; }
    void setFieldTypes(const std::unordered_map<uint64_t, uint32_t>* ft) { fieldTypes_ = ft; }

private:
    AbstractValue regs_[16];
    AbstractValue flags_[5];
    std::set<uint16_t> dispatchKeyRegs_;
    const pefix::PEFile* pe_ = nullptr;
    uint64_t imageBase_ = 0;
    std::unordered_map<uint16_t, uint64_t> initRegs_;
    std::set<uint16_t> initRegSet_;
    const std::unordered_map<uint32_t, uint32_t>* returnTypes_ = nullptr;
    const std::unordered_map<uint64_t, uint32_t>* fieldTypes_ = nullptr;
    std::unordered_map<uint16_t, uint32_t> typedPtrs_;

    void initState();
    void transfer(const pefix::Instr& instr);
    AbstractValue getVal(const pefix::Value& v);
    void setVal(const pefix::Value& v, AbstractValue av);
    void setFlag(int idx, AbstractValue av) { if (idx < 5) flags_[idx] = av; }
    AbstractValue getFlag(int idx) { return idx < 5 ? flags_[idx] : AbstractValue::Top(); }
    bool evalCC(pefix::CC cc);
    int evalCCResult(pefix::CC cc);
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
