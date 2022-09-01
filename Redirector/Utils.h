#pragma once
#ifndef UTILS_H
#define UTILS_H
#include "Based.h"

string ws2s(wstring str);
wstring s2ws(string str);
void log(const wchar_t* fmt, ...);
wstring ConvertIP(PSOCKADDR addr);
wstring GetProcessName(DWORD id);
bool checkBypassName(DWORD id);
bool checkHandleName(DWORD id);
#endif
