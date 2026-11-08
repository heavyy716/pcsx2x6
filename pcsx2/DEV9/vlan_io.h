// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "net.h"
#include "vlan_link.h"

// UDP "virtual cable" network backend (vs-rollback harness).
//
// Selected by setting PCSX2X6_VLAN=<host>:<port> (for example 127.0.0.1:47246) before the
// emulator starts; it then overrides DEV9/Eth EthApi. Each raw Ethernet frame the SMAP
// sends becomes one UDP datagram to that address, and each datagram received back is
// handed to the SMAP as a frame. A switch process (vs-rollback scripts/vlan_switch.py)
// relays frames between instances, so two emulators share one private layer-2 LAN.
//
// The SMAP MAC (written into the DEV9 EEPROM) comes from PCSX2X6_SMAP_MAC, or else
// PCSX2X6_VLAN_MAC, so instances on the same LAN don't collide. No internal DHCP/DNS
// server is used.
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
	VlanLink link;
	bool initialised = false;
	bool notedForeignDst = false;
};