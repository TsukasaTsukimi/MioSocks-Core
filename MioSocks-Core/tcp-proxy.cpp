#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include "socks5.h"

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

const int DEFAULT_BUFLEN = 1024;

int forward(SOCKET src, SOCKET dst)
{
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen;
    do
    {
        recvbuflen = recv(src, recvbuf, DEFAULT_BUFLEN, 0);
        if (recvbuflen > 0)
        {
            //printf("%s\n", recvbuf);
            send(dst, recvbuf, recvbuflen, 0);
        }
    } while (recvbuflen > 0);
    closesocket(src);
    closesocket(dst);
    return recvbuflen;
}

inline void process(SOCKET client)
{
    SOCKET target = INVALID_SOCKET;
    //----------------------
    // Create a SOCKET for connecting to server
    target = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (target == INVALID_SOCKET) {
        wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    // SOCKS5
    struct sockaddr_in socks5addr;
    socks5addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &(socks5addr.sin_addr));
    socks5addr.sin_port = htons(2801);

    SOCKS5 socks5((SOCKADDR*)&socks5addr,sizeof(socks5addr));

    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port of the server to be connected to.
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    inet_pton(AF_INET, "107.181.87.5", &(clientService.sin_addr));
    clientService.sin_port = htons(80);
    int iResult = socks5.Connect(target, &clientService, sizeof(clientService));
    if (iResult == SOCKET_ERROR) {
        wprintf(L"connect failed with error: %d\n", WSAGetLastError());
        closesocket(target);
        WSACleanup();
        return;
    }
    std::thread th1(forward, client, target);
    std::thread th2(forward, target, client);
    th1.detach();
    th2.detach();
}

int main()
{
    //----------------------
    // Initialize Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup failed with error: %ld\n", iResult);
        return 1;
    }
    //----------------------
    // Create a SOCKET for listening for
    // incoming connection requests.
    SOCKET ListenSocket;
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    sockaddr_in service;
    service.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &(service.sin_addr));
    service.sin_port = htons(2805);

    if (bind(ListenSocket,
        (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        wprintf(L"bind failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    //----------------------
    // Listen for incoming connection requests.
    // on the created socket
    if (listen(ListenSocket, 1) == SOCKET_ERROR) {
        wprintf(L"listen failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    //----------------------
    // Create a SOCKET for accepting incoming requests.
    SOCKET AcceptSocket;
    wprintf(L"Waiting for client to connect...\n");

    //----------------------
    // Accept the connection.
    while (1)
    {
        AcceptSocket = accept(ListenSocket, NULL, NULL);
        if (AcceptSocket == INVALID_SOCKET) {
            wprintf(L"accept failed with error: %ld\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
        else
        {
            wprintf(L"Client connected.\n");

            std::thread th(process, AcceptSocket);
            th.detach();
        }
    }

    // No longer need server socket
    closesocket(ListenSocket);

    WSACleanup();
    return 0;
}
