#include <griffin/int3.h>
#include <cstring>
#include <cstdio>

namespace griffin {

std::vector<Int3Site> scanInt3Sites(const pefix::PEFile& pe) {
    std::vector<Int3Site> sites;

    for (int si = 0; si < pe.numSections; si++) {
        char sname[9] = {};
        memcpy(sname, pe.sections[si].Name, 8);
        if (strcmp(sname, ".grfn1") != 0) continue;

        uint32_t secRVA = pe.sections[si].VirtualAddress;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;

        for (uint32_t pos = 0; pos + 30 < rawSz; pos++) {
            uint32_t off = rawOff + pos;
            if (pe.data[off] != 0xCC || pe.data[off+1] != 0x90 ||
                pe.data[off+2] != 0xCC ||
                pe.data[off+7] != 0x48 || pe.data[off+8] != 0xB8 ||
                pe.data[off+17] != 0x48 || pe.data[off+18] != 0xB8) continue;

            Int3Site site = {};
            site.siteRVA = secRVA + pos;
            memcpy(&site.constA, pe.data.data() + off + 9, 8);
            memcpy(&site.constB, pe.data.data() + off + 19, 8);
            site.targetRVA = 0;
            site.callOffset = 0;
            sites.push_back(site);
        }
    }

    return sites;
}

void resolveInt3Targets(std::vector<Int3Site>& sites, const pefix::PEFile& pe) {
    uint32_t soi = pe.nt->OptionalHeader.SizeOfImage;

    for (auto& site : sites) {
        uint32_t siteOff = pe.rvaToOffset(site.siteRVA);
        if (!siteOff || siteOff + 62 > pe.data.size()) continue;

        for (int c = 27; c < 45; c++) {
            if (pe.data[siteOff + c] != 0xE8) continue;

            int32_t callDisp = *(int32_t*)(pe.data.data() + siteOff + c + 1);
            uint32_t callTarget = site.siteRVA + c + 5 + callDisp;
            uint32_t ctOff = pe.rvaToOffset(callTarget);
            if (!ctOff || ctOff + 8 > pe.data.size()) continue;

            if (pe.data[ctOff] != 0xCC) continue;

            for (int j = 1; j < 8; j++) {
                if (pe.data[ctOff + j] != 0xE9) continue;

                int32_t jmpDisp = *(int32_t*)(pe.data.data() + ctOff + j + 1);
                uint32_t realTarget = callTarget + j + 5 + jmpDisp;

                if (realTarget < soi) {
                    site.targetRVA = realTarget;
                    site.callOffset = c;
                }
                break;
            }
            break;
        }

        if (site.targetRVA == 0 && siteOff + 200 < pe.data.size()) {
            uint32_t pos = 7;
            while (pos + 10 < 200 &&
                   pe.data[siteOff + pos] == 0x48 && pe.data[siteOff + pos + 1] == 0xB8) {
                pos += 10;
            }

            if (pos + 7 < 200 &&
                pe.data[siteOff + pos] == 0x49 && pe.data[siteOff + pos + 1] == 0xF7 &&
                pe.data[siteOff + pos + 2] == 0xC7) {
                pos += 7;
            }

            if (pos >= 27) {
                site.targetRVA = site.siteRVA + pos;
                site.callOffset = 0;
            }
        }
    }
}

Int3Stats patchInt3Sites(pefix::PEFile& pe, uint64_t imageBase, std::vector<Int3Site>& sites) {
    (void)imageBase;
    Int3Stats stats = {};
    stats.totalSites = (uint32_t)sites.size();

    for (auto& site : sites) {
        if (site.targetRVA == 0) continue;
        stats.resolved++;

        uint32_t siteOff = pe.rvaToOffset(site.siteRVA);
        if (!siteOff || siteOff + 7 > pe.data.size()) continue;

        if (site.callOffset > 0) {
            int32_t jmpDisp = (int32_t)(site.targetRVA - (site.siteRVA + 5));
            pe.data[siteOff + 0] = 0xE9;
            memcpy(pe.data.data() + siteOff + 1, &jmpDisp, 4);
            pe.data[siteOff + 5] = 0x90;
            pe.data[siteOff + 6] = 0x90;

            uint32_t nopEnd = siteOff + site.callOffset + 5;
            if (nopEnd <= pe.data.size()) {
                for (uint32_t n = siteOff + 7; n < nopEnd; n++)
                    pe.data[n] = 0x90;
            }
        } else {
            uint32_t blockLen = site.targetRVA - site.siteRVA;
            if (blockLen > 0 && blockLen < 200 && siteOff + blockLen <= pe.data.size()) {
                for (uint32_t n = 0; n < blockLen; n++)
                    pe.data[siteOff + n] = 0x90;
            }
        }

        stats.patched++;
    }

    return stats;
}

} // namespace griffin
