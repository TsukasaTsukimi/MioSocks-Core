#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

class SOCKS5
{
public:
	SOCKS5(SOCKET s, const sockaddr* name, int namelen);
	int Connect(SOCKET s, const sockaddr* name, int namelen);
private:
	const sockaddr* name;
	int namelen;
};