// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "net.h"

#include <chrono>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

// UDP "virtual cable" network backend (vs-rollback harness).
//
// Selected by setting PCSX2X6_VLAN=<host>:<port> (for example 127.0.0.1:47246) before the
// emulator starts; it then overrides DEV9/Eth EthApi. Each raw Ethernet frame the SMAP
// sends becomes one UDP datagram to that address, and each datagram received back is
// handed to the SMAP as a frame. A switch process (vs-rollback scripts/vlan_switch.py)
// relays frames between instances, so two emulators share one private layer-2 LAN.
//
// PCSX2X6_VLAN_MAC=aa:bb:cc:dd:ee:ff sets the SMAP MAC (written into the DEV9 EEPROM),
// so instances on the same LAN don't collide. No internal DHCP/DNS server is used.
class VlanAdapter : public NetAdapter
{
public:
	static bool IsRequested();

	VlanAdapter();
	~VlanAdapter() override;

	bool blocks() override { return false; }
	bool isInitialised() override { return initialised; }
	bool recv(NetPacket* pkt) override;
	bool send(NetPacket* pkt) override;
	void reloadSettings() override {}
	void close() override;

private:
	void SendHello();

#ifdef _WIN32
	using socket_t = SOCKET;
#else
	using socket_t = int;
#endif
	socket_t sock;
	sockaddr_in peer{};
	bool initialised = false;
	std::chrono::steady_clock::time_point lastHello{};
	bool notedForeignDst = false;
};
