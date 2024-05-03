#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <map>
#include "socks5.h"

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

const int DEFAULT_BUFLEN = 1024;

int Tcp2Socks_Listen();

struct NetTuple
{
	UINT32 SrcAddr;
	UINT16 SrcPort;
	UINT32 DstAddr;
	UINT16 DstPort;
};

extern NetTuple M[65536];