#pragma once
#include <cstdio>
#include <cstdarg>
#include <windows.h>

namespace cli {

static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

inline void ok(const char* fmt, ...) {
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    printf("[+] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    va_list args; va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

inline void fail(const char* fmt, ...) {
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    printf("[-] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    va_list args; va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

inline void warn(const char* fmt, ...) {
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
    printf("[!] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    va_list args; va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

inline void info(const char* fmt, ...) {
    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
    printf("[*] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    va_list args; va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

inline void detail(const char* fmt, ...) {
    SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
    printf("    ");
    va_list args; va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n");
}

} // namespace cli
