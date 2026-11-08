// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "vlan_link.h"
#include "LinkProbe.h"

#include "common/Console.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace
{
	constexpr char HELLO_MAGIC[8] = {'V', 'S', 'R', 'H', 'E', 'L', 'L', 'O'};
	constexpr int HELLO_SIZE = sizeof(HELLO_MAGIC) + 6;

#ifdef _WIN32
	using native_socket = SOCKET;
#else
	using native_socket = int;
#endif
	native_socket Native(std::uintptr_t s) { return static_cast<native_socket>(s); }
	std::uintptr_t Wrap(native_socket s) { return static_cast<std::uintptr_t>(s); }
} // namespace

static_assert(sizeof(sockaddr_in) <= 16, "VlanLink::peer too small");

std::string VlanLink::GetEnv(const char* name)
{
#ifdef _WIN32
	char* buf = nullptr;
	size_t len = 0;
	std::string ret;
	if (_dupenv_s(&buf, &len, name) == 0 && buf)
	{
		ret = buf;
		std::free(buf);
	}
	return ret;
#else
	const char* v = std::getenv(name);
	return v ? std::string(v) : std::string();
#endif
}

bool VlanLink::ParseMac(const std::string& s, u8 out[6])
{
	unsigned int b[6];
	if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return false;
	for (int i = 0; i < 6; i++)
	{
		if (b[i] > 0xFF)
			return false;
	}
	for (int i = 0; i < 6; i++)
		out[i] = static_cast<u8>(b[i]);
	return true;
}

VlanLink::~VlanLink()
{
	Close();
}

bool VlanLink::Open(const std::string& target_, const u8 mac_[6], const char* tag)
{
	Close();
	target = target_;
	std::memcpy(mac, mac_, 6);

	const size_t colon = target.rfind(':');
	if (colon == std::string::npos)
	{
		Console.Error("VLAN(%s): PCSX2X6_VLAN must be host:port, got '%s'", tag, target.c_str());
		return false;
	}
	const std::string host = target.substr(0, colon);
	const int port = std::atoi(target.c_str() + colon + 1);
	if (port <= 0 || port > 65535)
	{
		Console.Error("VLAN(%s): bad port in PCSX2X6_VLAN='%s'", tag, target.c_str());
		return false;
	}

#ifdef _WIN32
	if (!wsaStarted)
	{
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			Console.Error("VLAN(%s): WSAStartup failed", tag);
			return false;
		}
		wsaStarted = true;
	}
#endif

	std::memset(peer, 0, sizeof(peer));
	sockaddr_in& peerAddr = *reinterpret_cast<sockaddr_in*>(peer);
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = htons(static_cast<u16>(port));
	if (inet_pton(AF_INET, host.c_str(), &peerAddr.sin_addr) != 1)
	{
		addrinfo hints{};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		addrinfo* res = nullptr;
		if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
		{
			Console.Error("VLAN(%s): cannot resolve '%s'", tag, host.c_str());
			return false;
		}
		peerAddr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
		freeaddrinfo(res);
	}

	sock = Wrap(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
	if (sock == kInvalid)
	{
		Console.Error("VLAN(%s): socket() failed", tag);
		return false;
	}

	// Bind to an ephemeral local port; the switch learns it from our hello datagrams.
	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = 0;
	if (bind(Native(sock), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
	{
		Console.Error("VLAN(%s): bind() failed", tag);
		Close();
		return false;
	}

#ifdef _WIN32
	u_long nonblocking = 1;
	ioctlsocket(Native(sock), FIONBIO, &nonblocking);
	// Don't let an ICMP port-unreachable (switch not running yet) break later recvfrom calls.
	BOOL newBehavior = FALSE;
	DWORD bytesReturned = 0;
	WSAIoctl(Native(sock), SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior),
		nullptr, 0, &bytesReturned, nullptr, nullptr);
#else
	fcntl(Native(sock), F_SETFL, fcntl(Native(sock), F_GETFL, 0) | O_NONBLOCK);
#endif

	SendHello();
	{
		std::lock_guard<std::mutex> lk(helloMutex);
		keepaliveStop = false;
	}
	keepalive = std::thread(&VlanLink::KeepaliveLoop, this);
	Console.WriteLn(Color_StrongGreen, "VLAN(%s): %02x:%02x:%02x:%02x:%02x:%02x on UDP virtual LAN %s", tag,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], target.c_str());
	LinkProbe::Note("VLAN up (%s): switch=%s mac=%02x:%02x:%02x:%02x:%02x:%02x", tag, target.c_str(),
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return true;
}

void VlanLink::Close()
{
	StopKeepalive();
	if (sock != kInvalid)
	{
#ifdef _WIN32
		closesocket(Native(sock));
#else
		::close(Native(sock));
#endif
		sock = kInvalid;
	}
#ifdef _WIN32
	if (wsaStarted)
	{
		WSACleanup();
		wsaStarted = false;
	}
#endif
}

void VlanLink::SetMac(const u8 mac_[6])
{
	std::lock_guard<std::mutex> lk(helloMutex);
	std::memcpy(mac, mac_, 6);
	SendHelloLocked();
}

void VlanLink::SendHello()
{
	std::lock_guard<std::mutex> lk(helloMutex);
	SendHelloLocked();
}

void VlanLink::SendHelloLocked()
{
	if (sock == kInvalid)
		return;
	char hello[HELLO_SIZE];
	std::memcpy(hello, HELLO_MAGIC, sizeof(HELLO_MAGIC));
	std::memcpy(hello + sizeof(HELLO_MAGIC), mac, 6);
	sendto(Native(sock), hello, HELLO_SIZE, 0, reinterpret_cast<const sockaddr*>(peer), sizeof(sockaddr_in));
	lastHello = std::chrono::steady_clock::now();
}

void VlanLink::KeepaliveLoop()
{
	std::unique_lock<std::mutex> lk(helloMutex);
	while (!keepaliveStop)
	{
		if (std::chrono::steady_clock::now() - lastHello >= std::chrono::seconds(1))
			SendHelloLocked();
		keepaliveCv.wait_for(lk, std::chrono::seconds(1), [this] { return keepaliveStop; });
	}
}

void VlanLink::StopKeepalive()
{
	{
		std::lock_guard<std::mutex> lk(helloMutex);
		keepaliveStop = true;
	}
	keepaliveCv.notify_all();
	if (keepalive.joinable())
		keepalive.join();
}

int VlanLink::Recv(u8* buf, int cap)
{
	if (sock == kInvalid)
		return 0;

	// Keep the switch's port table fresh (and survive a switch restart).
	bool due;
	{
		std::lock_guard<std::mutex> lk(helloMutex);
		due = std::chrono::steady_clock::now() - lastHello > std::chrono::seconds(1);
	}
	if (due)
		SendHello();

	for (;;)
	{
		const int got = static_cast<int>(::recvfrom(Native(sock), reinterpret_cast<char*>(buf), cap, 0, nullptr, nullptr));
		if (got <= 0)
			return 0;
		if (got < 14)
			continue;
		if (got == HELLO_SIZE && std::memcmp(buf, HELLO_MAGIC, sizeof(HELLO_MAGIC)) == 0)
			continue;
		return got;
	}
}

void VlanLink::Send(const void* data, int len)
{
	if (sock == kInvalid)
		return;
	sendto(Native(sock), static_cast<const char*>(data), len, 0, reinterpret_cast<const sockaddr*>(peer), sizeof(sockaddr_in));
}
