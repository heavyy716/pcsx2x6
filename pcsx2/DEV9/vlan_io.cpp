// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#include "vlan_io.h"
#include "LinkProbe.h"

#include "common/Console.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <mstcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using PacketReader::MAC_Address;

namespace
{
	constexpr char HELLO_MAGIC[8] = {'V', 'S', 'R', 'H', 'E', 'L', 'L', 'O'};

	std::string GetEnv(const char* name)
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

	bool ParseMac(const std::string& s, MAC_Address* mac)
	{
		unsigned int b[6];
		if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
			return false;
		for (int i = 0; i < 6; i++)
		{
			if (b[i] > 0xFF)
				return false;
			mac->bytes[i] = static_cast<u8>(b[i]);
		}
		return true;
	}

#ifdef _WIN32
	const auto kInvalidSocket = INVALID_SOCKET;
	void CloseSocket(SOCKET s) { closesocket(s); }
#else
	const int kInvalidSocket = -1;
	void CloseSocket(int s) { ::close(s); }
#endif
} // namespace

bool VlanAdapter::IsRequested()
{
	return !GetEnv("PCSX2X6_VLAN").empty();
}

VlanAdapter::VlanAdapter()
	: sock(kInvalidSocket)
{
	const std::string target = GetEnv("PCSX2X6_VLAN");
	const size_t colon = target.rfind(':');
	if (colon == std::string::npos)
	{
		Console.Error("DEV9: VLAN: PCSX2X6_VLAN must be host:port, got '%s'", target.c_str());
		return;
	}
	const std::string host = target.substr(0, colon);
	const int port = std::atoi(target.c_str() + colon + 1);
	if (port <= 0 || port > 65535)
	{
		Console.Error("DEV9: VLAN: bad port in PCSX2X6_VLAN='%s'", target.c_str());
		return;
	}

	const std::string macStr = GetEnv("PCSX2X6_VLAN_MAC");
	if (!macStr.empty())
	{
		MAC_Address mac;
		if (ParseMac(macStr, &mac))
			SetMACAddress(&mac);
		else
			Console.Error("DEV9: VLAN: ignoring malformed PCSX2X6_VLAN_MAC='%s'", macStr.c_str());
	}

#ifdef _WIN32
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		Console.Error("DEV9: VLAN: WSAStartup failed");
		return;
	}
#endif

	peer.sin_family = AF_INET;
	peer.sin_port = htons(static_cast<u16>(port));
	if (inet_pton(AF_INET, host.c_str(), &peer.sin_addr) != 1)
	{
		addrinfo hints{};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		addrinfo* res = nullptr;
		if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
		{
			Console.Error("DEV9: VLAN: cannot resolve '%s'", host.c_str());
			return;
		}
		peer.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
		freeaddrinfo(res);
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == kInvalidSocket)
	{
		Console.Error("DEV9: VLAN: socket() failed");
		return;
	}

	// Bind to an ephemeral local port; the switch learns it from our hello datagrams.
	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = 0;
	if (bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
	{
		Console.Error("DEV9: VLAN: bind() failed");
		CloseSocket(sock);
		sock = kInvalidSocket;
		return;
	}

#ifdef _WIN32
	u_long nonblocking = 1;
	ioctlsocket(sock, FIONBIO, &nonblocking);
	// Don't let an ICMP port-unreachable (switch not running yet) break later recvfrom calls.
	BOOL newBehavior = FALSE;
	DWORD bytesReturned = 0;
	WSAIoctl(sock, SIO_UDP_CONNRESET, &newBehavior, sizeof(newBehavior),
		nullptr, 0, &bytesReturned, nullptr, nullptr);
#else
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
#endif

	initialised = true;
	SendHello();
	Console.WriteLn(Color_StrongGreen, "DEV9: VLAN: SMAP %02x:%02x:%02x:%02x:%02x:%02x on UDP virtual LAN %s",
		ps2MAC.bytes[0], ps2MAC.bytes[1], ps2MAC.bytes[2], ps2MAC.bytes[3], ps2MAC.bytes[4], ps2MAC.bytes[5],
		target.c_str());
	LinkProbe::Note("VLAN up: switch=%s mac=%02x:%02x:%02x:%02x:%02x:%02x", target.c_str(),
		ps2MAC.bytes[0], ps2MAC.bytes[1], ps2MAC.bytes[2], ps2MAC.bytes[3], ps2MAC.bytes[4], ps2MAC.bytes[5]);
}

VlanAdapter::~VlanAdapter()
{
	close();
#ifdef _WIN32
	if (initialised)
		WSACleanup();
#endif
}

void VlanAdapter::close()
{
	if (sock != kInvalidSocket)
	{
		CloseSocket(sock);
		sock = kInvalidSocket;
	}
}

void VlanAdapter::SendHello()
{
	if (sock == kInvalidSocket)
		return;
	char hello[sizeof(HELLO_MAGIC) + 6];
	std::memcpy(hello, HELLO_MAGIC, sizeof(HELLO_MAGIC));
	std::memcpy(hello + sizeof(HELLO_MAGIC), ps2MAC.bytes, 6);
	sendto(sock, hello, static_cast<int>(sizeof(hello)), 0, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
	lastHello = std::chrono::steady_clock::now();
}

bool VlanAdapter::recv(NetPacket* pkt)
{
	if (sock == kInvalidSocket)
		return false;

	// Keep the switch's port table fresh (and survive a switch restart).
	if (std::chrono::steady_clock::now() - lastHello > std::chrono::seconds(1))
		SendHello();

	for (;;)
	{
		const int got = static_cast<int>(::recvfrom(sock, pkt->buffer, static_cast<int>(sizeof(pkt->buffer)), 0, nullptr, nullptr));
		if (got <= 0)
			return false;
		if (got < 14)
			continue;

		const MAC_Address& dst = *reinterpret_cast<const MAC_Address*>(&pkt->buffer[0]);
		const MAC_Address& src = *reinterpret_cast<const MAC_Address*>(&pkt->buffer[6]);
		// The switch already decides what reaches this port, so only drop our own echoes.
		// Unicast to a MAC other than the EEPROM one is still delivered (and noted once),
		// in case the game programs its own station address.
		if (src == ps2MAC)
			continue;
		const bool group = (dst.bytes[0] & 1) != 0;
		if (!group && dst != ps2MAC && !notedForeignDst)
		{
			notedForeignDst = true;
			LinkProbe::Note("VLAN: unicast for %02x:%02x:%02x:%02x:%02x:%02x (not our EEPROM MAC) delivered anyway",
				dst.bytes[0], dst.bytes[1], dst.bytes[2], dst.bytes[3], dst.bytes[4], dst.bytes[5]);
		}

		pkt->size = got;
		return true;
	}
}

bool VlanAdapter::send(NetPacket* pkt)
{
	if (sock == kInvalidSocket)
		return false;
	sendto(sock, pkt->buffer, pkt->size, 0, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
	return true;
}
