#include "socks5.h"
#include <iostream>

SOCKS5::SOCKS5(const sockaddr* name, int namelen)
{
	proxy = name;
	proxylen = namelen;
}

int SOCKS5::Connect(SOCKET s, const sockaddr_in* name, int namelen)
{
	// Connect Socks5 Server
	{
		int ret = connect(s, proxy, proxylen);
		if (ret == SOCKET_ERROR)
		{
			return ret;
		}
	}

	// Send Authentication Request
	{
		AuthRequest auth(AuthMethod_Unauthorized);
		int len = auth.Size();
		do
		{
			int ret = send(s, auth, len, 0);
			if (ret == SOCKET_ERROR)
			{
				return ret;
			}
			len -= ret;
		} while (len > 0);
	}

	// Recv Authentication Response
	{
		AuthResponse auth;
		int len = auth.Size();
		int ret = recv(s, auth, len, 0);
		if (ret == SOCKET_ERROR)
		{
			return ret;
		}
	}

	// SOCKS request
	{
		Requests request(Command_Connect, name);
		int len = request.Size();
		do
		{
			int ret = send(s, request, len, 0);
			if (ret == SOCKET_ERROR)
			{
				return ret;
			}
			len -= ret;
		} while (len > 0);
	}

	// SOCKS reply
	{
		Replies reply;
		int len = reply.Size();
		int ret = recv(s, reply, len, 0);
		if (ret == SOCKET_ERROR)
		{
			return ret;
		}
		printf("Socks5 connected: %u, %u\n", reply.VER, name->sin_port);
	}
	
	return 0;
}

SOCKS5::AuthRequest::AuthRequest(AuthMethod method)
{
	VER = Version_5;
	NMETHODS = 1;
	METHODS[0] = method;
}

SOCKS5::AuthResponse::AuthResponse()
{
	VER = Version_5;
	METHOD = AuthMethod_Unauthorized;
}

SOCKS5::Requests::Requests(Command cmd, const sockaddr_in* name)
{
	VER = Version_5;
	CMD = cmd;
	RSV = 0x00;
	switch (name->sin_family)
	{
	case AF_INET:
	{
		ATYP = AddressType_Ipv4;
		const in_addr* addr = (const in_addr*)&name->sin_addr;
		DST_ADDR.ipv4.Byte[0] = addr->S_un.S_un_b.s_b1;
		DST_ADDR.ipv4.Byte[1] = addr->S_un.S_un_b.s_b2;
		DST_ADDR.ipv4.Byte[2] = addr->S_un.S_un_b.s_b3;
		DST_ADDR.ipv4.Byte[3] = addr->S_un.S_un_b.s_b4;
		break;
	}
	case AF_INET6:
	{
		ATYP = AddressType_Ipv6;
		const in6_addr* addr = (const in6_addr*)&name->sin_addr;
		for (int i = 0; i < 16; i++)
			DST_ADDR.ipv6.Byte[i] = addr->u.Byte[i];
		break;
	}
	}
	DST_PORT = name->sin_port;
}

SOCKS5::Replies::Replies()
	:bind_addr()
{
	VER = Version_Undefined;
	REP = ReplyType_Undefined;
	RSV = 0x00;
	ATYP = AddressType_Undefined;
	DST_PORT = 0x00;
}