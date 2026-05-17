#include <griffin/log.h>
#include <cstdio>

namespace griffin::log {

static Sink g_sink = nullptr;

void set_sink(Sink sink) { g_sink = sink; }

static void emit(Level lvl, const char* fmt, va_list args) {
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, args);
    if (g_sink) {
        g_sink((int)lvl, buf);
        return;
    }
    const char* pre = "";
    switch (lvl) {
        case OK:     pre = "[+] "; break;
        case FAIL:   pre = "[-] "; break;
        case WARN:   pre = "[!] "; break;
        case INFO:   pre = "[*] "; break;
        case DETAIL: pre = "    "; break;
        case RAW:    pre = "";     break;
    }
    fputs(pre, stdout);
    fputs(buf, stdout);
    if (lvl != RAW) fputc('\n', stdout);
}

#define DEFINE_LEVEL(name, lvl) \
    void name(const char* fmt, ...) { \
        va_list args; va_start(args, fmt); emit(lvl, fmt, args); va_end(args); \
    }

DEFINE_LEVEL(ok,     OK)
DEFINE_LEVEL(fail,   FAIL)
DEFINE_LEVEL(warn,   WARN)
DEFINE_LEVEL(info,   INFO)
DEFINE_LEVEL(detail, DETAIL)
DEFINE_LEVEL(raw,    RAW)

} // namespace griffin::log
