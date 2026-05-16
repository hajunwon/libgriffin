#pragma once
#include <pefix/x86_64/ir.h>
#include <cstdio>

namespace griffin {

class Output {
public:
    void emitText(const char* path, const pefix::Func& func, uint64_t imageBase);
    void emitIDC(const char* path, const pefix::Func& func, uint64_t imageBase);

private:
    void printValue(FILE* f, const pefix::Value& v, pefix::Width defaultWidth = pefix::Width::W64);
    void printInstr(FILE* f, const pefix::Instr& instr);
};

} // namespace griffin
