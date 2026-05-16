#pragma once

#include <pefix/x86_64/ir.h>

namespace griffin {
    // Extended pseudo-ops for MBA simplification results
    constexpr pefix::Op MBA_XOR  = (pefix::Op)0x100;
    constexpr pefix::Op MBA_OR   = (pefix::Op)0x101;
    constexpr pefix::Op MBA_AND  = (pefix::Op)0x102;
    constexpr pefix::Op MBA_ADD  = (pefix::Op)0x103;
    constexpr pefix::Op MBA_SUB  = (pefix::Op)0x104;
    constexpr pefix::Op OPAQUE_TRUE  = (pefix::Op)0x110;
    constexpr pefix::Op OPAQUE_FALSE = (pefix::Op)0x111;
}

#include <griffin/dispatch.h>
#include <griffin/int3.h>
#include <griffin/jmpres.h>
#include <griffin/mba.h>
#include <griffin/patch.h>
#include <griffin/output.h>
