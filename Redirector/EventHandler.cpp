#include "EventHandler.h"

#include "DNSHandler.h"
#include "TCPHandler.h"
#include "Utils.h"

extern bool filterParent;
extern bool filterTCP;
extern bool filterUDP;
extern bool filterDNS;

extern bool dnsOnly;

extern bool filterSelf;

extern vector<wstring> bypassList;
extern vector<wstring> handleList;

extern USHORT tcpListen;

DWORD CurrentID = 0;

mutex udpContextLock;
map<ENDPOINT_ID, SocksHelper::PUDP> udpContext;

atomic_ullong UP = { 0 };
atomic_ullong DL = { 0 };

bool eh_init()
{
	CurrentID = GetCurrentProcessId();

	if (!DNSHandler::INIT())
		return false;

	if (!TCPHandler::INIT())
		return false;

	return true;
}

void eh_free()
{
	lock_guard<mutex> lg(udpContextLock);

	TCPHandler::FREE();

	for (std::pair<ENDPOINT_ID, SocksHelper::PUDP> i : udpContext)
		delete i.second;
	udpContext.clear();

	UP = 0;
	DL = 0;
}

void threadStart()
{

}

void threadEnd()
{

}

void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	if (CurrentID == info->processId && !filterSelf)
	{
		nf_tcpDisableFiltering(id);
		return;
	}

	if (!filterTCP)
	{
		nf_tcpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][tcpConnectRequest][" << id << "][" << info->processId << "][!filterTCP] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][tcpConnectRequest][%llu][%1u][!filterTCP] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	if (checkBypassName(info->processId))
	{
		nf_tcpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][tcpConnectRequest][" << id << "][" << info->processId << "][checkBypassName] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][tcpConnectRequest][%llu][%1u][checkBypassName] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	if (!checkHandleName(info->processId))
	{
		nf_tcpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][tcpConnectRequest][" << id << "][" << info->processId << "][!checkHandleName] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][tcpConnectRequest][%llu][%1u][!checkHandleName] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	if (info->ip_family != AF_INET && info->ip_family != AF_INET6)
	{
		nf_tcpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][tcpConnectRequest][" << id << "][" << info->processId << "][!IPv4 && !IPv6] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][tcpConnectRequest][%llu][%1u][!IPv4 && !IPv6] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	SOCKADDR_IN6 client;
	memcpy(&client, info->localAddress, sizeof(SOCKADDR_IN6));

	SOCKADDR_IN6 remote;
	memcpy(&remote, info->remoteAddress, sizeof(SOCKADDR_IN6));

	if (info->ip_family == AF_INET)
	{
		auto addr = (PSOCKADDR_IN)info->remoteAddress;
		addr->sin_family = AF_INET;
		addr->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		addr->sin_port = tcpListen;
	}

	if (info->ip_family == AF_INET6)
	{
		auto addr = (PSOCKADDR_IN6)info->remoteAddress;
		IN6ADDR_SETLOOPBACK(addr);
		addr->sin6_port = tcpListen;
	}

	TCPHandler::CreateHandler(client, remote);
	//wcout << "[Redirector][EventHandler][tcpConnectRequest][" << id << "][" << info->processId << "] " << ConvertIP((PSOCKADDR)&client) << " -> " << ConvertIP((PSOCKADDR)&remote) << endl;
	log(L"[Redirector][EventHandler][tcpConnectRequest][%llu][%1u] %s -> %s\n", id, info->processId, ConvertIP((PSOCKADDR)&client).c_str(), ConvertIP((PSOCKADDR)&remote).c_str());
}

void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	//wcout << "[Redirector][EventHandler][tcpConnected][" << id << "][" << info->processId << "][" << ConvertIP((PSOCKADDR)info->remoteAddress) << "] " << GetProcessName(info->processId) << endl;
	log(L"[Redirector][EventHandler][tcpConnected][%llu][%1u][%s] %s\n", id, info->processId, ConvertIP((PSOCKADDR)info->remoteAddress).c_str(), GetProcessName(info->processId).c_str());
}

void tcpCanSend(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void tcpSend(ENDPOINT_ID id, const char* buffer, int length)
{
	UP += length;

	nf_tcpPostSend(id, buffer, length);
}

void tcpCanReceive(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void tcpReceive(ENDPOINT_ID id, const char* buffer, int length)
{
	DL += length;

	nf_tcpPostReceive(id, buffer, length);
}

void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO info)
{
	SOCKADDR_IN6 client;
	memcpy(&client, info->localAddress, sizeof(SOCKADDR_IN6));

	TCPHandler::DeleteHandler(client);

	log(L"[Redirector][EventHandler][tcpClosed][%llu][%lu]\n", id, info->processId);
}

void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO info)
{
	if (CurrentID == info->processId && !filterSelf)
	{
		nf_udpDisableFiltering(id);
		return;
	}

	if (!filterUDP)
	{
		if (!filterDNS) nf_udpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][udpCreated][" << id << "][" << info->processId << "][!filterUDP] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][udpCreated][%llu][%1u][!filterUDP] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	if (checkBypassName(info->processId))
	{
		if (dnsOnly) nf_udpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][udpCreated][" << id << "][" << info->processId << "][checkBypassName] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][udpCreated][%llu][%1u][checkBypassName] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	if (!checkHandleName(info->processId))
	{
		if (dnsOnly) nf_udpDisableFiltering(id);

		//wcout << "[Redirector][EventHandler][udpCreated][" << id << "][" << info->processId << "][!checkHandleName] " << GetProcessName(info->processId) << endl;
		log(L"[Redirector][EventHandler][udpCreated][%llu][%1u][!checkHandleName] %s\n", id, info->processId, GetProcessName(info->processId).c_str());
		return;
	}

	//wcout << "[Redirector][EventHandler][udpCreated][" << id << "][" << info->processId << "] " << GetProcessName(info->processId) << endl;
	log(L"[Redirector][EventHandler][udpCreated][%llu][%1u] %s\n", id, info->processId, GetProcessName(info->processId).c_str());

	lock_guard<mutex> lg(udpContextLock);
	udpContext[id] = new SocksHelper::UDP();
}

void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST info)
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(info);
}

void udpCanSend(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void udpSend(ENDPOINT_ID id, const unsigned char* target, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	if (DNSHandler::IsDNS((PSOCKADDR_IN6)target))
	{
		if (!filterDNS)
		{
			nf_udpPostSend(id, target, buffer, length, options);

			//wcout << "[Redirector][EventHandler][udpSend][" << id << "] B DNS to " << ConvertIP((PSOCKADDR)target) << endl;
			log(L"[Redirector][EventHandler][udpSend][%llu] B DNS to %s\n", id, ConvertIP((PSOCKADDR)target).c_str());
			return;
		}
		else
		{
			UP += length;
			DNSHandler::CreateHandler(id, (PSOCKADDR_IN6)target, buffer, length, options);

			//wcout << "[Redirector][EventHandler][udpSend][" << id << "] H DNS to " << ConvertIP((PSOCKADDR)target) << endl;
			log(L"[Redirector][EventHandler][udpSend][%llu] H DNS to %s\n", id, ConvertIP((PSOCKADDR)target).c_str());
			return;
		}
	}

	udpContextLock.lock();
	if (udpContext.find(id) == udpContext.end())
	{
		udpContextLock.unlock();

		nf_udpPostSend(id, target, buffer, length, options);
		return;
	}
	auto remote = udpContext[id];
	udpContextLock.unlock();

	if (remote->tcpSocket == INVALID_SOCKET && !remote->Associate())
		return;

	if (remote->udpSocket == INVALID_SOCKET)
	{
		if (!remote->CreateUDP())
			return;

		auto option = (PNF_UDP_OPTIONS)new char[sizeof(NF_UDP_OPTIONS) + options->optionsLength]();
		memcpy(option, options, sizeof(NF_UDP_OPTIONS) + options->optionsLength - 1);

		thread(udpReceiveHandler, id, remote, option).detach();
	}

	if (remote->Send((PSOCKADDR_IN6)target, buffer, length) == length)
		UP += length;
}

void udpCanReceive(ENDPOINT_ID id)
{
	UNREFERENCED_PARAMETER(id);
}

void udpReceive(ENDPOINT_ID id, const unsigned char* target, const char* buffer, int length, PNF_UDP_OPTIONS options)
{
	nf_udpPostReceive(id, target, buffer, length, options);
}

void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO info)
{
	UNREFERENCED_PARAMETER(info);

	log(L"[Redirector][EventHandler][udpClosed][%llu]\n", id);

	lock_guard<mutex> lg(udpContextLock);
	if (udpContext.find(id) != udpContext.end())
	{
		delete udpContext[id];

		udpContext.erase(id);
	}
}

void udpReceiveHandler(ENDPOINT_ID id, SocksHelper::PUDP remote, PNF_UDP_OPTIONS options)
{
	char buffer[1458];

	while (remote->tcpSocket != INVALID_SOCKET && remote->udpSocket != INVALID_SOCKET)
	{
		SOCKADDR_IN6 target;

		int length = remote->Read(&target, buffer, sizeof(buffer), NULL);
		if (length == 0 || length == SOCKET_ERROR)
			break;

		DL += length;

		nf_udpPostReceive(id, (unsigned char*)&target, buffer, length, options);
	}

	delete[] options;
}
