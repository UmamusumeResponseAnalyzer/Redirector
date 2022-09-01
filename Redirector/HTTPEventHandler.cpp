#include "EventHandler.h"
#include "Utils.h"

extern bool filterLoopback;
extern bool filterIntranet;
extern wstring tgtHost;
extern wstring tgtPort;
extern int proxyPid;
unsigned char redirectToAddress[NF_MAX_ADDRESS_LENGTH];

struct ORIGINAL_CONN_INFO
{
	unsigned char	remoteAddress[NF_MAX_ADDRESS_LENGTH];
	std::vector<char>	pendedSends;
};

typedef std::map<ENDPOINT_ID, ORIGINAL_CONN_INFO> tConnInfoMap;
tConnInfoMap m_connInfoMap;

void ht_threadStart()
{
	// Initialize thread specific stuff
}

void ht_threadEnd()
{
	// Uninitialize thread specific stuff
}

//
// TCP events
//

void ht_tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
	if (checkBypassName(pConnInfo->processId))
	{
		nf_tcpDisableFiltering(id);

		log(L"[Redirector][ht_EventHandler][tcpConnectRequest][%llu][%1u][checkBypassName] %s\n", id, pConnInfo->processId, GetProcessName(pConnInfo->processId).c_str());
		return;
	}

	if (!checkHandleName(pConnInfo->processId))
	{
		nf_tcpDisableFiltering(id);

		log(L"[Redirector][ht_EventHandler][tcpConnectRequest][%llu][%1u][!checkHandleName] %s\n", id, pConnInfo->processId, GetProcessName(pConnInfo->processId).c_str());
		return;
	}

	sockaddr* pAddr = (sockaddr*)pConnInfo->remoteAddress;
	int addrLen = (pAddr->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);

	ORIGINAL_CONN_INFO oci;
	memcpy(oci.remoteAddress, pConnInfo->remoteAddress, sizeof(oci.remoteAddress));

	// Save the original remote address
	m_connInfoMap[id] = oci;

	// Redirect the connection if it is not already redirected
	if (memcmp(pAddr, redirectToAddress, addrLen) != 0 &&
		proxyPid != pConnInfo->processId)
	{
		// Change the remote address
		memcpy(pConnInfo->remoteAddress, redirectToAddress, sizeof(pConnInfo->remoteAddress));
		pConnInfo->processId = proxyPid;

		// Filtering is required only for HTTP/SOCKS tunneling.
		// The first incoming packet will be a response from proxy that must be skipped.
		pConnInfo->filteringFlag |= NF_FILTER;
	}
}

void ht_tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
}

void ht_tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
	m_connInfoMap.erase(id);
}

void ht_tcpReceive(ENDPOINT_ID id, const char* buf, int len)
{
	tConnInfoMap::iterator it;

	it = m_connInfoMap.find(id);
	if (it != m_connInfoMap.end())
	{
		if (!it->second.pendedSends.empty())
		{
			nf_tcpPostSend(id, &it->second.pendedSends[0], (int)it->second.pendedSends.size());
		}

		m_connInfoMap.erase(id);
		// The first packet is a response from proxy server.
		// Skip it.

		return;
	}

	// Send the packet to application
	nf_tcpPostReceive(id, buf, len);

	// Don't filter the subsequent packets (optimization)
	nf_tcpDisableFiltering(id);
}

void ht_tcpSend(ENDPOINT_ID id, const char* buf, int len)
{
	tConnInfoMap::iterator it = m_connInfoMap.find(id);

	if (it != m_connInfoMap.end())
	{
		char request[200];
		wchar_t addrStr[MAX_PATH] = L"";
		sockaddr* pAddr;
		DWORD dwLen;
		tConnInfoMap::iterator it = m_connInfoMap.find(id);

		// Generate CONNECT request using saved original remote address

		if (it == m_connInfoMap.end())
			return;

		pAddr = (sockaddr*)&it->second.remoteAddress;
		dwLen = sizeof(addrStr);

		WSAAddressToString((LPSOCKADDR)pAddr,
			(pAddr->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
			NULL,
			addrStr,
			&dwLen);

		_snprintf_s(request, sizeof(request), "CONNECT %ls HTTP/1.1\r\n\r\n", addrStr);

		// Send the request first
		nf_tcpPostSend(id, request, (int)strlen(request));

		it->second.pendedSends.insert(it->second.pendedSends.end(), buf, buf + len);
		return;
	}

	// Send the packet to server
	nf_tcpPostSend(id, buf, len);
}

void ht_tcpCanReceive(ENDPOINT_ID id)
{
}

void ht_tcpCanSend(ENDPOINT_ID id)
{
}

//
// UDP events
//

void ht_udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
{
}

void ht_udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq)
{
}

void ht_udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
{
}

void ht_udpReceive(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buf, int len, PNF_UDP_OPTIONS options)
{
}

void ht_udpSend(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buf, int len, PNF_UDP_OPTIONS options)
{
}

void ht_udpCanReceive(ENDPOINT_ID id)
{
}

void ht_udpCanSend(ENDPOINT_ID id)
{
}

NF_EventHandler ht_EventHandler = {
	ht_threadStart,
	ht_threadEnd,
	ht_tcpConnectRequest,
	ht_tcpConnected,
	ht_tcpClosed,
	ht_tcpReceive,
	ht_tcpSend,
	ht_tcpCanReceive,
	ht_tcpCanSend,
	ht_udpCreated,
	ht_udpConnectRequest,
	ht_udpClosed,
	ht_udpReceive,
	ht_udpSend,
	ht_udpCanReceive,
	ht_udpCanSend
};

extern "C" {
	__declspec(dllexport) BOOL __cdecl ht_start() {
		int addrLength = sizeof(redirectToAddress);
		NF_RULE rule;
		WSADATA wsaData;
		::WSAStartup(MAKEWORD(2, 2), &wsaData);
		nf_adjustProcessPriviledges();
		WSAStringToAddress(const_cast<LPWSTR>(tgtHost.append(L":").append(tgtPort).c_str()), AF_INET, NULL, (LPSOCKADDR)&redirectToAddress, &addrLength);
		nf_init("netfilter2", &ht_EventHandler);

		if (!filterLoopback)
		{
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "127.0.0.1", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.0.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET6;
			rule.remoteIpAddress[15] = 1;
			memset(rule.remoteIpAddressMask, 0xff, sizeof(rule.remoteIpAddressMask));
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);
		}

		if (!filterIntranet)
		{
			/* 10.0.0.0/8 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "10.0.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.0.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 100.64.0.0/10 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "100.64.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.192.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 169.254.0.0/16 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "169.254.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.255.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 172.16.0.0/12 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "100.64.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.240.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 192.0.0.0/24 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "192.0.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.255.255.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 192.168.0.0/16 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "192.168.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.255.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);

			/* 198.18.0.0/15 */
			memset(&rule, 0, sizeof(NF_RULE));
			rule.ip_family = AF_INET;
			inet_pton(AF_INET, "198.18.0.0", rule.remoteIpAddress);
			inet_pton(AF_INET, "255.254.0.0", rule.remoteIpAddressMask);
			rule.filteringFlag = NF_ALLOW;
			nf_addRule(&rule, FALSE);
		}

		memset(&rule, 0, sizeof(rule));
		rule.protocol = IPPROTO_TCP;
		rule.direction = NF_D_OUT;
		rule.filteringFlag = NF_INDICATE_CONNECT_REQUESTS;
		rule.processId = 0;
		nf_addRule(&rule, FALSE);

		return TRUE;
	}
}