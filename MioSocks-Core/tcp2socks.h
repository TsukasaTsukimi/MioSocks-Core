#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include "socks5.h"

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

const int DEFAULT_BUFLEN = 1024;

int Tcp2Socks_Listen();