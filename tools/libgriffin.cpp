#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include "cli.h"
#include <string>
#include <vector>

#include <pefix/pefix.h>
#include <griffin/griffin.h>

static void printUsage(const char* exe) {
    printf("griffin -- PE deobfuscation tool (INT3 + JMP flatten + MBA simplify)\n\n");
    printf("Usage: %s <input.exe> [options]\n\n", exe);
    printf("Options:\n");
    printf("  -o <output.exe>   Output path (default: <input>_deobf.exe)\n");
    printf("  --all             Apply all deobfuscation passes (default behavior)\n");
    printf("  --int3            INT3 handler resolution only\n");
    printf("  --jmp             Indirect JMP resolution only\n");
    printf("  --mba             MBA simplification only\n");
    printf("  --dry-run         Analyze only, do not write output\n");
    printf("  --verbose         Print detailed pass info\n");
    printf("\nWith no options, all safe deobfuscation passes are applied.\n\n");
}

static std::string makeOutputName(const char* input) {
    std::string s(input);
    auto dot = s.rfind('.');
    if (dot == std::string::npos)
        return s + "_deobf";
    return s.substr(0, dot) + "_deobf" + s.substr(dot);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const char* inputPath = nullptr;
    const char* outputPath = nullptr;
    bool doInt3 = false, doJmp = false, doMba = false;
    bool dryRun = false, verbose = false;
    bool explicitPass = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            doInt3 = doJmp = doMba = true;
        } else if (strcmp(argv[i], "--int3") == 0) {
            doInt3 = true; explicitPass = true;
        } else if (strcmp(argv[i], "--jmp") == 0) {
            doJmp = true; explicitPass = true;
        } else if (strcmp(argv[i], "--mba") == 0) {
            doMba = true; explicitPass = true;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dryRun = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (argv[i][0] != '-') {
            inputPath = argv[i];
        } else {
            printf("[!] Unknown option: %s\n", argv[i]);
            printUsage(argv[0]);
            return 1;
        }
    }

    if (!inputPath) {
        printf("[!] No input file specified.\n");
        printUsage(argv[0]);
        return 1;
    }

    // Default: all passes
    if (!explicitPass) {
        doInt3 = doJmp = doMba = true;
    }

    // Generate output name
    std::string outStr;
    if (!outputPath) {
        outStr = makeOutputName(inputPath);
        outputPath = outStr.c_str();
    }

    pefix::PEFile pe;
    if (!pe.load(inputPath)) { cli::fail("Failed to load: %s", inputPath); return 1; }
    if (!pe.parse()) { cli::fail("Failed to parse PE: %s", inputPath); return 1; }

    uint64_t imageBase = pe.nt->OptionalHeader.ImageBase;
    cli::info("Input: %s", inputPath);
    cli::info("ImageBase: 0x%llX", (unsigned long long)imageBase);

    if (doInt3) {
        auto sites = griffin::scanInt3Sites(pe);
        griffin::resolveInt3Targets(sites, pe);
        auto stats = griffin::patchInt3Sites(pe, imageBase, sites);
        cli::ok("INT3: %u sites, %u resolved, %u patched", stats.totalSites, stats.resolved, stats.patched);
    }

    if (doJmp) {
        std::vector<uint32_t> funcRVAs;
        auto resolved = griffin::resolveIndirectJumps(pe, imageBase, funcRVAs);
        auto stats = griffin::patchIndirectJumps(pe, imageBase, resolved);
        cli::ok("JMP: %u indirect, %u resolved, %u patched", stats.totalIndirect, stats.resolved, stats.patched);

        auto calls = griffin::resolveIndirectCalls(pe, imageBase);
        auto cstats = griffin::patchIndirectCalls(pe, imageBase, calls);
        if (verbose)
            cli::detail("Calls: %u scanned, %u resolved, %u patched", cstats.totalScanned, cstats.resolved, cstats.patched);
    }

    if (doMba) {
        cli::info("MBA simplification (per-function, requires CFG)");
    }

    if (dryRun) {
        cli::info("Dry run -- no output written");
    } else {
        if (pe.save(outputPath))
            cli::ok("Output: %s", outputPath);
        else {
            cli::fail("Failed to write: %s", outputPath);
            return 1;
        }
    }

    return 0;
}
