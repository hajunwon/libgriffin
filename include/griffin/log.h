#pragma once
#include <cstdarg>

namespace griffin::log {

enum Level { OK = 0, FAIL, WARN, INFO, DETAIL, RAW };

using Sink = void(*)(int level, const char* message);

void set_sink(Sink sink);

void ok(const char* fmt, ...);
void fail(const char* fmt, ...);
void warn(const char* fmt, ...);
void info(const char* fmt, ...);
void detail(const char* fmt, ...);
void raw(const char* fmt, ...);

} // namespace griffin::log
