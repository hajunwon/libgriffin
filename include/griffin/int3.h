#pragma once
#include <pefix/pe.h>
#include <cstdint>
#include <vector>

namespace griffin {

struct Int3Site {
    uint32_t siteRVA;
    uint64_t constA;
    uint64_t constB;
    uint32_t targetRVA;
    uint32_t callOffset;
};

struct Int3Stats {
    uint32_t totalSites;
    uint32_t resolved;
    uint32_t patched;
};

std::vector<Int3Site> scanInt3Sites(const pefix::PEFile& pe);
void resolveInt3Targets(std::vector<Int3Site>& sites, const pefix::PEFile& pe);
Int3Stats patchInt3Sites(pefix::PEFile& pe, uint64_t imageBase, std::vector<Int3Site>& sites);

} // namespace griffin
