#include <griffin/output.h>
#include <cstring>

namespace griffin {

using namespace pefix;

void Output::printValue(FILE* f, const Value& v, Width defaultWidth) {
    (void)defaultWidth;
    switch (v.kind) {
    case Value::REG:
        if (v.width == Width::W32) fprintf(f, "%s", regName32(v.reg));
        else fprintf(f, "%s", regName(v.reg));
        break;
    case Value::IMM:
        if (v.imm < 0 && v.imm > -0x10000)
            fprintf(f, "-0x%llX", (unsigned long long)-v.imm);
        else if (v.imm >= 0 && v.imm < 256)
            fprintf(f, "0x%llX", (unsigned long long)v.imm);
        else
            fprintf(f, "0x%llX", (unsigned long long)(uint64_t)v.imm);
        break;
    case Value::MEM: {
        const char* szPrefix = "";
        if (v.width == Width::W8) szPrefix = "byte ";
        else if (v.width == Width::W16) szPrefix = "word ";
        else if (v.width == Width::W32) szPrefix = "dword ";
        else if (v.width == Width::W64) szPrefix = "qword ";
        fprintf(f, "%s[", szPrefix);
        bool first = true;
        if (v.reg != Reg::NONE) { fprintf(f, "%s", regName(v.reg)); first = false; }
        if (v.index != Reg::NONE) {
            if (!first) fprintf(f, "+");
            fprintf(f, "%s", regName(v.index));
            if (v.scale > 1) fprintf(f, "*%d", v.scale);
            first = false;
        }
        if (v.imm != 0 || first) {
            if (v.imm >= 0) { if (!first) fprintf(f, "+"); fprintf(f, "0x%llX", (unsigned long long)v.imm); }
            else fprintf(f, "-0x%llX", (unsigned long long)-v.imm);
        }
        fprintf(f, "]");
        break;
    }
    case Value::LABEL:
        fprintf(f, "0x%llX", (unsigned long long)v.imm);
        break;
    default:
        break;
    }
}

void Output::printInstr(FILE* f, const Instr& instr) {
    if (instr.dead) return;

    fprintf(f, "  %llX  ", (unsigned long long)instr.addr);

    const char* mnemonic = opName(instr.op);

    if (instr.op == Op::JCC || instr.op == Op::CMOV || instr.op == Op::SETcc) {
        fprintf(f, "%s%s", mnemonic, ccName(instr.cc));
    } else {
        fprintf(f, "%s", mnemonic);
    }

    bool hasDst = !instr.dst.isNone();
    bool hasSrc1 = !instr.src1.isNone();
    bool hasSrc2 = !instr.src2.isNone();

    if (hasDst || hasSrc1) fprintf(f, " ");

    if (instr.op == Op::JMP || instr.op == Op::JCC || instr.op == Op::CALL) {
        printValue(f, instr.dst);
    } else {
        if (hasDst) { printValue(f, instr.dst); }
        if (hasSrc1 && hasDst) fprintf(f, ", ");
        if (hasSrc1 && !(instr.dst.isReg() && instr.src1.isReg() && instr.dst.reg == instr.src1.reg)) {
            printValue(f, instr.src1);
            if (hasSrc2) fprintf(f, ", ");
        }
        if (hasSrc2) { printValue(f, instr.src2); }
    }

    if (instr.simplified) fprintf(f, "  ; [simplified]");
    fprintf(f, "\n");
}

void Output::emitText(const char* path, const Func& func, uint64_t imageBase) {
    (void)imageBase;
    FILE* f = stdout;
    if (path) {
        fopen_s(&f, path, "w");
        if (!f) { fprintf(stderr, "[!] Cannot open %s\n", path); return; }
    }

    fprintf(f, "=== Deobfuscated: 0x%llX ===\n", (unsigned long long)func.entryAddr);
    fprintf(f, "Blocks: %zu, Instructions: %u (live: %u)\n",
            func.blocks.size(), func.totalInstrs(), func.liveInstrs());
    fprintf(f, "Frame size: 0x%X\n", func.frameSize);

    if (!func.callTargets.empty()) {
        fprintf(f, "Calls:");
        for (auto t : func.callTargets) fprintf(f, " 0x%llX", (unsigned long long)t);
        fprintf(f, "\n");
    }
    fprintf(f, "\n");

    for (uint32_t i = 0; i < func.blocks.size(); i++) {
        auto& blk = func.blocks[i];
        if (blk.isDeadCode) continue;

        fprintf(f, "Block %u (0x%llX - 0x%llX, %zu instrs)",
                i, (unsigned long long)blk.startAddr, (unsigned long long)blk.endAddr,
                blk.instrs.size());
        if (blk.isTrampoline) fprintf(f, " [trampoline]");
        if (!blk.succs.empty()) {
            fprintf(f, " -> {");
            for (size_t j = 0; j < blk.succs.size(); j++) {
                if (j > 0) fprintf(f, ", ");
                fprintf(f, "B%u", blk.succs[j]);
            }
            fprintf(f, "}");
        }
        fprintf(f, "\n");

        for (auto& instr : blk.instrs) {
            printInstr(f, instr);
        }
        fprintf(f, "\n");
    }

    if (path && f != stdout) fclose(f);
}

void Output::emitIDC(const char* path, const Func& func, uint64_t imageBase) {
    (void)imageBase;
    FILE* f = nullptr;
    fopen_s(&f, path, "w");
    if (!f) { fprintf(stderr, "[!] Cannot open %s\n", path); return; }

    fprintf(f, "// Deobfuscation annotations\n");
    fprintf(f, "// Function: 0x%llX\n", (unsigned long long)func.entryAddr);
    fprintf(f, "#include <idc.idc>\n\n");
    fprintf(f, "static main() {\n");

    for (auto& blk : func.blocks) {
        if (blk.isDeadCode) continue;
        fprintf(f, "    set_cmt(0x%llX, \"Block start (%zu instrs)\", 0);\n",
                (unsigned long long)blk.startAddr, blk.instrs.size());

    }

    fprintf(f, "    msg(\"Annotations applied\\n\");\n");
    fprintf(f, "}\n");
    fclose(f);
    printf("[+] IDC annotations written: %s\n", path);
}

} // namespace griffin
