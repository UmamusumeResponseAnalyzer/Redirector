#include "Utils.h"

extern bool filterParent;
extern bool enableLog;
extern vector<wstring> bypassList;
extern vector<wstring> handleList;

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

wstring ConvertIP(PSOCKADDR addr)
{
	WCHAR buffer[MAX_PATH] = L"";
	DWORD bufferLength = MAX_PATH;

	if (addr->sa_family == AF_INET)
	{
		WSAAddressToStringW(addr, sizeof(SOCKADDR_IN), NULL, buffer, &bufferLength);
	}
	else
	{
		WSAAddressToStringW(addr, sizeof(SOCKADDR_IN6), NULL, buffer, &bufferLength);
	}

	return buffer;
}

wstring GetProcessName(DWORD id)
{
	if (id == 0)
	{
		return L"Idle";
	}

	if (id == 4)
	{
		return L"System";
	}

	wchar_t name[MAX_PATH];
	if (!nf_getProcessNameFromKernel(id, name, MAX_PATH))
	{
		if (!nf_getProcessNameW(id, name, MAX_PATH))
		{
			return L"Unknown";
		}
	}

	wchar_t data[MAX_PATH];
	if (GetLongPathNameW(name, data, MAX_PATH))
	{
		return data;
	}

	return name;
}

bool checkBypassName(DWORD id)
{
	auto name = GetProcessName(id);

	for (size_t i = 0; i < bypassList.size(); i++)
	{
		if (regex_search(name, wregex(bypassList[i])))
		{
			return true;
		}
	}

	return false;
}

bool checkHandleName(DWORD id)
{
	{
		auto name = GetProcessName(id);

		for (size_t i = 0; i < handleList.size(); i++)
		{
			if (regex_search(name, wregex(handleList[i])))
			{
				return true;
			}
		}
	}

	if (filterParent)
	{
		PROCESSENTRY32W PE;
		memset(&PE, 0, sizeof(PROCESSENTRY32W));
		PE.dwSize = sizeof(PROCESSENTRY32W);

		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		if (!Process32FirstW(hSnapshot, &PE))
		{
			CloseHandle(hSnapshot);
			return false;
		}

		do {
			if (PE.th32ProcessID == id)
			{
				auto name = GetProcessName(PE.th32ParentProcessID);

				for (size_t i = 0; i < handleList.size(); i++)
				{
					if (regex_search(name, wregex(handleList[i])))
					{
						CloseHandle(hSnapshot);
						return true;
					}
				}
			}
		} while (Process32NextW(hSnapshot, &PE));

		CloseHandle(hSnapshot);
	}

	return false;
}