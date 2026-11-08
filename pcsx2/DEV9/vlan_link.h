// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Defs.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

// One port on the vs-rollback UDP "virtual cable" LAN (scripts/vlan_switch.py).
//
// Each raw Ethernet frame (no FCS) is one UDP datagram to the switch at PCSX2X6_VLAN=host:port.
// About once a second the port also sends a 14-byte hello ("VSRHELLO" + 6-byte MAC) so the
// switch learns it before the guest transmits anything. A keepalive thread keeps sending hellos
// while the guest is idle (e.g. before the game loads its USB LAN driver), so the switch doesn't
// age the port out. Shared by the DEV9 SMAP backend
// (VlanAdapter) and the emulated Namco USB LAN board (usb-namco-uenet).
class VlanLink
{
public:
	VlanLink() = default;
	~VlanLink();
	VlanLink(const VlanLink&) = delete;
	VlanLink& operator=(const VlanLink&) = delete;

	static std::string GetEnv(const char* name);
	static bool ParseMac(const std::string& s, u8 mac[6]);

	// target is "host:port". tag prefixes console and LinkProbe messages ("SMAP", "USB").
	bool Open(const std::string& target, const u8 mac[6], const char* tag);
	void Close();
	bool IsOpen() const { return sock != kInvalid; }
	const std::string& Target() const { return target; }

	// Changes the MAC announced in hellos (sends one immediately).
	void SetMac(const u8 mac[6]);

	// Non-blocking. Returns the datagram length, or 0 if nothing is pending. Hello datagrams
	// and anything shorter than an Ethernet header are skipped. Also refreshes the hello.
	int Recv(u8* buf, int cap);
	void Send(const void* data, int len);

private:
	void SendHello();
	void SendHelloLocked();
	void KeepaliveLoop();
	void StopKeepalive();

	// Socket handle and sockaddr_in kept opaque so this header doesn't pull in winsock2.h.
	static constexpr std::uintptr_t kInvalid = ~static_cast<std::uintptr_t>(0);
	std::uintptr_t sock = kInvalid;
	alignas(8) u8 peer[16] = {};
	bool wsaStarted = false;
	u8 mac[6] = {};
	std::string target;
	std::chrono::steady_clock::time_point lastHello{};

	// Guards mac, lastHello and keepaliveStop; hellos are sent from the keepalive thread too.
	std::mutex helloMutex;
	std::condition_variable keepaliveCv;
	bool keepaliveStop = false;
	std::thread keepalive;
};