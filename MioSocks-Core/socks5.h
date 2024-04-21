#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

#pragma comment(lib, "Ws2_32.lib")

class SOCKS5
{
public:
	SOCKS5(const sockaddr* name, int namelen);
	int Connect(SOCKET s, const sockaddr_in* name, int namelen);
private:
	const sockaddr* proxy;
	int proxylen;

	enum Version : uint8_t
	{
		Version_Undefined = 0x00,  // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
		Version_5 = 0x05,  // '05' Socks5 Protocol Version
	};
	enum AuthMethod : uint8_t
	{
		// The values currently defined for METHOD are:
		AuthMethod_Unauthorized = 0x00, // '00' NO AUTHENTICATION REQUIRED
		AuthMethod_GssApi = 0x01, // '01' GSSAPI
		AuthMethod_UsernamePassword = 0x02, // '02' USERNAME/PASSWORD
		// '03' to X'7F' IANA ASSIGNED
		// '80' to X'FE' RESERVED FOR PRIVATE METHODS
		AuthMethod_Undefined = 0xfe, // 'FF' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
		AuthMethod_NoAcceptableMethods = 0xff, // 'FF' NO ACCEPTABLE METHODS
	};

	enum Command : uint8_t
	{
		Command_Undefined = 0x00, // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
		Command_Connect = 0x01, // '01' CONNECT
		Command_Bind = 0x02, // '02' BIND
		Command_UdpAssociate = 0x03, // '03' UDP ASSOCIATE
	};

	enum AddressType : uint8_t
	{
		AddressType_Undefined = 0x00, // '00' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
		AddressType_Ipv4 = 0x01, // '01' IP V4 address
		AddressType_DomainName = 0x03, // '03' DOMAINNAME
		AddressType_Ipv6 = 0x04, // '04' IP V6 address
	};

	enum ReplyType : uint8_t
	{
		ReplyType_Succeeded = 0x00, // '00' succeeded
		ReplyType_SocksFailure = 0x01, // '01' general SOCKS server failure
		ReplyType_NotAllowed = 0x02, // '02' connection not allowed by ruleset
		ReplyType_NetUnreachable = 0x03, // '03' Network unreachable
		ReplyType_HostUnreachable = 0x04, // '04' Host unreachable
		ReplyType_ConnRefused = 0x05, // '05' Connection refused
		ReplyType_TtlExpired = 0x06, // '06' TTL expired
		ReplyType_UnsupportedCommand = 0x07, // '07' Command not supported
		ReplyType_UnsupportedAddrType = 0x08, // '08' Address type not supported
		// '09' to X'FF' unassigned
		ReplyType_Undefined = 0xFF, // 'FF' UNDEFINED VALUE. IMPLEMENTATION ONLY! DOESN'T EXISTS RFC1928!
	};

	struct Ipv4Address
	{
		uint8_t     Byte[4];
	};

	struct Ipv6Address
	{
		uint16_t    Byte[16];
	};

	struct DomainName
	{
		uint8_t       length;
		uint8_t       name[255];
	};

	struct AuthRequest
	{
		Version VER;
		uint8_t	NMETHODS;
		AuthMethod	METHODS[255];

		AuthRequest(AuthMethod method);
		operator const char* () const { return reinterpret_cast<const char*>(this); }
		int Size() const { return static_cast<int>(offsetof(AuthRequest, METHODS) + NMETHODS); }
	};

	struct AuthResponse
	{
		Version VER;
		AuthMethod METHOD;

		AuthResponse();
		operator char* () { return reinterpret_cast<char*>(this); }
		int Size() const { return static_cast<int>(sizeof(*this)); }
	};

	struct Requests
	{
		Version VER;
		Command CMD;
		uint8_t RSV;
		AddressType ATYP;
		union
		{
			Ipv4Address     ipv4;
			Ipv6Address     ipv6;
			DomainName      domain;
		} DST_ADDR;
		uint16_t DST_PORT;

		Requests(Command cmd, const sockaddr_in* name);
		operator const char* () const { return reinterpret_cast<const char*>(this); }
		int Size() const
		{
			int len = offsetof(Requests, DST_ADDR) + sizeof(DST_PORT);
			switch (ATYP)
			{
			case AddressType_Ipv4:
				return len + sizeof(DST_ADDR.ipv4);
			case AddressType_DomainName:
				return len + sizeof(DST_ADDR.domain.length) + DST_ADDR.domain.length;
			case AddressType_Ipv6:
				return len + sizeof(DST_ADDR.ipv6);
			default:
				return 0;
			}
		}
	};

	struct Replies
	{
		Version VER;
		ReplyType REP;
		uint8_t RSV;
		AddressType ATYP;
		union
		{
			Ipv4Address     ipv4;
			Ipv6Address     ipv6;
			DomainName      domain;
		} bind_addr;
		uint16_t DST_PORT;

		Replies();
		operator char* () { return reinterpret_cast<char*>(this); }
		int Size() const { return static_cast<int>(offsetof(Replies, bind_addr)); }
	};
};