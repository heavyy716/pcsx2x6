// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#include "vlan_io.h"
#include "LinkProbe.h"

#include "common/Console.h"

#include <string>

using PacketReader::MAC_Address;

bool VlanAdapter::IsRequested()
{
	return !VlanLink::GetEnv("PCSX2X6_VLAN").empty();
}

VlanAdapter::VlanAdapter()
{
	const char* macVar = "PCSX2X6_SMAP_MAC";
	std::string macStr = VlanLink::GetEnv(macVar);
	if (macStr.empty())
	{
		macVar = "PCSX2X6_VLAN_MAC";
		macStr = VlanLink::GetEnv(macVar);
	}
	if (!macStr.empty())
	{
		MAC_Address mac;
		if (VlanLink::ParseMac(macStr, mac.bytes))
			SetMACAddress(&mac);
		else
			Console.Error("DEV9: VLAN: ignoring malformed %s='%s'", macVar, macStr.c_str());
	}

	initialised = link.Open(VlanLink::GetEnv("PCSX2X6_VLAN"), ps2MAC.bytes, "SMAP");
}

VlanAdapter::~VlanAdapter()
{
	close();
}

void VlanAdapter::close()
{
	link.Close();
}

bool VlanAdapter::recv(NetPacket* pkt)
{
	for (;;)
	{
		const int got = link.Recv(reinterpret_cast<u8*>(pkt->buffer), static_cast<int>(sizeof(pkt->buffer)));
		if (got <= 0)
			return false;

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
	if (!link.IsOpen())
		return false;
	link.Send(pkt->buffer, pkt->size);
	return true;
}