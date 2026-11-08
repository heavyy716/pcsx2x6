// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "USB/deviceproxy.h"

// Namco "System246 UE PCB" (USB 0B9A:0500): the USB Ethernet board the System 246/256
// Gundam versus titles use for the cabinet link. The games load AN986.IRX ("AN986 1.80.0"),
// an ADMtek Pegasus class driver whose probe table includes this ID. See uenet-model.h for
// the register/framing model. Frames go to the vs-rollback UDP virtual LAN
// (PCSX2X6_VLAN=host:port, MAC from PCSX2X6_VLAN_MAC) and enumeration, vendor requests and
// frames are logged through LinkProbe (PCSX2X6_LINKLOG).
namespace usb_namco_uenet
{
	class UeNetDevice final : public DeviceProxy
	{
	public:
		USBDevice* CreateDevice(SettingsInterface& si, u32 port, u32 subtype) const override;
		const char* Name() const override;
		const char* TypeName() const override;
		const char* IconName() const override;
		bool Freeze(USBDevice* dev, StateWrapper& sw) const override;
	};
} // namespace usb_namco_uenet
