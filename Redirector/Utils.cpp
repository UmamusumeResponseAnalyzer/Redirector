#include "Utils.h"

extern bool enableLog;
string ws2s(wstring str)
{
	auto length = WideCharToMultiByte(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), NULL, 0, NULL, NULL);
	auto buffer = new char[length + 1]();

	WideCharToMultiByte(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), buffer, length, NULL, NULL);

	auto data = string(buffer);
	delete[] buffer;

	return data;
}

wstring s2ws(string str)
{
	auto length = MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), NULL, 0);
	auto buffer = new wchar_t[length + 1]();

	MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), buffer, length);

	auto data = wstring(buffer);
	delete[] buffer;

	return data;
}

void log(const wchar_t* fmt, ...) {
	if (!enableLog) return;
	va_list args;
	va_start(args, fmt);
	vwprintf(fmt, args);
	va_end(args);
}