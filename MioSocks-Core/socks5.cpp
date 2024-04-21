#include "socks5.h"

SOCKS5::SOCKS5(SOCKET s, const sockaddr* name, int namelen)
{
	this->name = name;
	this->namelen = namelen;
}

int SOCKS5::Connect(SOCKET s, const sockaddr* name, int namelen)
{
	return 0;
}