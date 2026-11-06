// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Defs.h"

// Arcade link investigation logger (vs-rollback harness).
//
// Enabled by setting the environment variable PCSX2X6_LINKLOG to a file path before
// starting the emulator. Optional PCSX2X6_LINKPCAP=<path> also writes every SMAP frame
// (TX and RX) to a Wireshark-readable pcap file.
//
// Logged events:
//   MMIO  - IOP accesses to DEV9/SPEED/SMAP, ACCORE/ACUART, unknown arcade ranges,
//           SIO0/SIO1, USB and i.LINK. Deduplicated per (dir, width, address): the first
//           four hits and every power-of-two hit count are written, with the value.
//   ETH   - every SMAP TX/RX frame with a one-line decode.
//   IRX   - every IOP library registered through loadcore RegisterLibraryEntries.
//   SUM   - per-address hit totals, written when DEV9 closes.
namespace LinkProbe
{
	extern bool enabled;

	void Init();
	void Shutdown();

	void IopAccess(char dir, u32 addr, int width, u32 value);
	void Frame(const char* dir, const void* data, int len);
	void Note(const char* fmt, ...);

	// True for IOP physical addresses the probe wants to see.
	static __fi bool IsWatched(u32 addr)
	{
		const u32 t = addr >> 16;
		if (t == 0x1000) // DEV9 expansion: SPEED, SMAP, ATA, flash
			return true;
		// Arcade board MMIO (ACCORE, ACUART, ACJV, ACATA, unknown), minus the plain memories
		// ACRAM (0x14xx) and ACSRAM (0x1250), which would only flood the log.
		if (t >= 0x1200 && t < 0x1F00 && (t & 0xFF00) != 0x1400 && t != 0x1250)
			return true;
		if (t == 0x1F80)
		{
			const u32 o = addr & 0xFFFF;
			if (o >= 0x1040 && o < 0x1060) // SIO0 / SIO1
				return true;
			if (o >= 0x1600 && o < 0x1700) // USB OHCI
				return true;
			if (o >= 0x8400 && o < 0x8580) // i.LINK (IEEE1394)
				return true;
		}
		return false;
	}
} // namespace LinkProbe
