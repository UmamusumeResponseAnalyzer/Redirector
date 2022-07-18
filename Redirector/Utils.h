#pragma once
#ifndef UTILS_H
#define UTILS_H
#include "Based.h"

string ws2s(wstring str);
wstring s2ws(string str);
void enable_log(bool option);
void log(const char* fmt, ...);
#endif
