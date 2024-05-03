#include <iostream>
#include <winsock2.h>
#include "windivert.h"
#include "tcp2socks.h"
#include <thread>

#pragma comment(lib,"WinDivert.lib")
#pragma comment(lib,"Ws2_32.lib")

const int MAXBUF = 65536;

NetTuple M[65536];

int main()
{
	std::thread th(Tcp2Socks_Listen);
	th.detach();
	HANDLE handle;          // WinDivert handle
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packetLen;

	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;

	UINT32 target;
	UINT32 proxy;
	WinDivertHelperParseIPv4Address("5.87.181.107", &target);
	WinDivertHelperParseIPv4Address("1.0.0.127", &proxy);

	// Open some filter
	handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		// Handle error
		exit(1);
	}

	// Main capture-modify-inject loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr))
		{
			// Handle recv error
			continue;
		}

		// Modify packet.
		WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL,
			NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);

		if (ip_header == NULL || tcp_header == NULL)
		{
			printf("failed to parse packet :%d \n", GetLastError());
			continue;
		}

		if (ip_header->Version == 4)
		{
			if (tcp_header->SrcPort == htons(2805))
			{
				printf("[<-]%u:%u %u:%u\n", ip_header->SrcAddr, htons(tcp_header->SrcPort), ip_header->DstAddr, htons(tcp_header->DstPort));
				UINT32 dst_addr = ip_header->DstAddr;
				UINT16 dst_port = ntohs(tcp_header->DstPort);
				tcp_header->SrcPort = htons(M[dst_port].DstPort);
				ip_header->DstAddr = ip_header->SrcAddr;
				ip_header->SrcAddr = dst_addr;
				addr.Outbound = FALSE;
			}
			else if (/*ip_header->DstAddr == target && */tcp_header->DstPort == htons(443) || tcp_header->DstPort == htons(80))
			{
				printf("[->]%u:%u %u:%u\n", ip_header->SrcAddr, htons(tcp_header->SrcPort), ip_header->DstAddr, htons(tcp_header->DstPort));
				UINT32 srcaddr = ip_header->SrcAddr;
				UINT16 srcport = ntohs(tcp_header->SrcPort);
				UINT32 dstaddr = ip_header->DstAddr;
				UINT16 dstport = ntohs(tcp_header->DstPort);
				M[srcport] = { srcaddr, srcport, dstaddr, dstport };
				

				UINT32 dst_addr = ip_header->DstAddr;
				tcp_header->DstPort = htons(2805);
				ip_header->DstAddr = ip_header->SrcAddr;
				ip_header->SrcAddr = dst_addr;
				addr.Outbound = FALSE;
			}
		}

		WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
		if (!WinDivertSend(handle, packet, packetLen, NULL, &addr))
		{
			// Handle send error
			continue;
		}
	}
}