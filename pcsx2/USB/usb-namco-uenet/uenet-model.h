// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#pragma once

// Register-level model of the Namco "System246 UE PCB" USB LAN board (ADMtek Pegasus
// family) as driven by the System 246/256 AN986.IRX driver. Header-only and free of PCSX2
// dependencies so it can be unit tested on its own (vs-rollback tests/uenet).
//
// Reverse-engineered AN986 behaviour this model follows:
//  - Registers: vendor request 0xF0 (IN) reads wLength bytes from wIndex, 0xF1 (OUT) writes
//    them. Multi-byte writes are applied in order, so the control byte written last triggers.
//  - EEPROM: write {offset, 0, 0, READ} at 0x20, poll 0x23 for DONE, read the word at 0x21.
//    Words 0..2 are the station address.
//  - MII: write {phy, lo, hi, reg|READ/WRITE} at 0x25, poll 0x28 for DONE, data at 0x26.
//    The driver scans PHY addresses 0..31 for BMSR != 0xFFFF with link+autoneg-complete set.
//  - TX (bulk OUT): u16 LE frame length + frame; one pad byte follows when (len + 2) % 64 == 0.
//  - RX (bulk IN): u16 LE L, frame (>= 60 bytes), 4 CRC bytes, status (low 5 bits = errors),
//    one more byte; L = frame + 8 and the driver drops transfers shorter than 68 bytes.

#include <cstdint>
#include <cstring>
#include <vector>

namespace usb_namco_uenet
{
	class UeNetModel
	{
	public:
		static constexpr uint8_t REG_ETH_CTRL0 = 0x00;
		static constexpr uint8_t REG_ETH_CTRL1 = 0x01;
		static constexpr uint8_t REG_ETH_ID = 0x10;
		static constexpr uint8_t REG_EPROM_OFFSET = 0x20;
		static constexpr uint8_t REG_EPROM_DATA = 0x21;
		static constexpr uint8_t REG_EPROM_CTRL = 0x23;
		static constexpr uint8_t REG_PHY_ADDR = 0x25;
		static constexpr uint8_t REG_PHY_DATA = 0x26;
		static constexpr uint8_t REG_PHY_CTRL = 0x28;

		static constexpr uint8_t EPROM_WRITE = 0x01;
		static constexpr uint8_t EPROM_READ = 0x02;
		static constexpr uint8_t EPROM_DONE = 0x04;
		static constexpr uint8_t PHY_WRITE = 0x20;
		static constexpr uint8_t PHY_READ = 0x40;
		static constexpr uint8_t PHY_DONE = 0x80;
		static constexpr uint8_t ETH_CTRL1_RESET_MAC = 0x08; // self-clearing; drivers poll until it reads 0

		static constexpr int PHY_ADDRESS = 1;
		static constexpr int MIN_FRAME = 60;
		static constexpr int MIN_TX_FRAME = 14;
		static constexpr int MAX_TX_FRAME = 1536;
		static constexpr int RX_OVERHEAD = 8;
		static constexpr int BULK_MPS = 64;

		// Last side effect, for logging by the caller.
		enum class Event
		{
			None,
			EepromRead,
			EepromWrite,
			PhyRead,
			PhyWrite,
			MacReset,
		};
		struct LastOp
		{
			Event ev = Event::None;
			int addr = 0; // EEPROM offset or PHY address
			int reg = 0;  // PHY register
			uint16_t value = 0;
		};

		uint8_t regs[256] = {};
		uint16_t eeprom[64] = {};
		uint16_t phy[32] = {};
		LastOp last;

		void Init(const uint8_t mac[6])
		{
			std::memset(eeprom, 0, sizeof(eeprom));
			for (int i = 0; i < 3; i++)
				eeprom[i] = static_cast<uint16_t>(mac[i * 2] | (mac[i * 2 + 1] << 8));
			Reset();
		}

		void Reset()
		{
			std::memset(regs, 0, sizeof(regs));
			for (int i = 0; i < 3; i++)
			{
				regs[REG_ETH_ID + i * 2] = static_cast<uint8_t>(eeprom[i] & 0xFF);
				regs[REG_ETH_ID + i * 2 + 1] = static_cast<uint8_t>(eeprom[i] >> 8);
			}
			std::memset(phy, 0, sizeof(phy));
			phy[0] = 0x1000;  // BMCR: autoneg enabled
			phy[1] = 0x782D;  // BMSR: 100FD/100HD/10FD/10HD, autoneg complete, link up, ext caps
			phy[2] = 0x0022;  // PHYID1 (ADMtek-style)
			phy[3] = 0x5610;  // PHYID2
			phy[4] = 0x01E1;  // ANAR: 100FD 100HD 10FD 10HD, 802.3
			phy[5] = 0x45E1;  // ANLPAR: partner same + ACK
			phy[6] = 0x0001;  // ANER
			tx_buf.clear();
			tx_pad_pending = false;
			last = {};
		}

		void GetMac(uint8_t mac[6]) const { std::memcpy(mac, &regs[REG_ETH_ID], 6); }
		bool RxEnabled() const { return regs[REG_ETH_CTRL0] != 0; }

		uint16_t PhyRead(int addr, int reg) const
		{
			if (addr != PHY_ADDRESS)
				return 0xFFFF;
			return phy[reg & 0x1F];
		}

		void PhyWrite(int addr, int reg, uint16_t v)
		{
			if (addr != PHY_ADDRESS)
				return;
			reg &= 0x1F;
			if (reg == 0)
				v &= static_cast<uint16_t>(~0x8200); // reset and restart-autoneg self-clear
			if (reg == 1 || reg == 2 || reg == 3 || reg == 5)
				return; // read-only
			phy[reg] = v;
		}

		void ReadRegs(int index, uint8_t* out, int n) const
		{
			for (int i = 0; i < n; i++)
				out[i] = regs[(index + i) & 0xFF];
		}

		void WriteRegs(int index, const uint8_t* in, int n)
		{
			for (int i = 0; i < n; i++)
				WriteReg((index + i) & 0xFF, in[i]);
		}

		void WriteReg(int r, uint8_t v)
		{
			regs[r] = v;
			if (r == REG_ETH_CTRL1 && (v & ETH_CTRL1_RESET_MAC))
			{
				// MAC reset completes instantly. Keep the MAC address, GPIO and filter
				// registers the driver programmed; only drop in-flight TX state.
				regs[REG_ETH_CTRL1] = static_cast<uint8_t>(v & ~ETH_CTRL1_RESET_MAC);
				tx_buf.clear();
				tx_pad_pending = false;
				last = {Event::MacReset, 0, 0, v};
			}
			else if (r == REG_EPROM_CTRL)
			{
				const int off = regs[REG_EPROM_OFFSET] & 0x3F;
				if (v & EPROM_READ)
				{
					const uint16_t w = eeprom[off];
					regs[REG_EPROM_DATA] = static_cast<uint8_t>(w & 0xFF);
					regs[REG_EPROM_DATA + 1] = static_cast<uint8_t>(w >> 8);
					last = {Event::EepromRead, off, 0, w};
				}
				else if (v & EPROM_WRITE)
				{
					const uint16_t w = static_cast<uint16_t>(regs[REG_EPROM_DATA] | (regs[REG_EPROM_DATA + 1] << 8));
					eeprom[off] = w;
					last = {Event::EepromWrite, off, 0, w};
				}
				regs[REG_EPROM_CTRL] = static_cast<uint8_t>((v & ~(EPROM_READ | EPROM_WRITE)) | EPROM_DONE);
			}
			else if (r == REG_PHY_CTRL)
			{
				const int addr = regs[REG_PHY_ADDR] & 0x1F;
				const int reg = v & 0x1F;
				if (v & PHY_READ)
				{
					const uint16_t d = PhyRead(addr, reg);
					regs[REG_PHY_DATA] = static_cast<uint8_t>(d & 0xFF);
					regs[REG_PHY_DATA + 1] = static_cast<uint8_t>(d >> 8);
					last = {Event::PhyRead, addr, reg, d};
				}
				else if (v & PHY_WRITE)
				{
					const uint16_t d = static_cast<uint16_t>(regs[REG_PHY_DATA] | (regs[REG_PHY_DATA + 1] << 8));
					PhyWrite(addr, reg, d);
					last = {Event::PhyWrite, addr, reg, d};
				}
				regs[REG_PHY_CTRL] = static_cast<uint8_t>(reg | PHY_DONE);
			}
		}

		// Feeds one bulk OUT packet (the OHCI splits a transfer into 64-byte packets).
		// onFrame(const uint8_t* frame, int len) runs for every complete frame.
		// Returns the number of framing errors (bad length headers) detected.
		template <typename F>
		int FeedTx(const uint8_t* data, int n, F&& onFrame)
		{
			int errors = 0;
			if (n <= 0)
				return 0;
			if (tx_pad_pending && tx_buf.empty() && n == 1)
			{
				tx_pad_pending = false;
				return 0;
			}
			tx_pad_pending = false;
			tx_buf.insert(tx_buf.end(), data, data + n);
			while (tx_buf.size() >= 2)
			{
				const int len = tx_buf[0] | (tx_buf[1] << 8);
				if (len < MIN_TX_FRAME || len > MAX_TX_FRAME)
				{
					errors++;
					tx_buf.clear();
					break;
				}
				if (static_cast<int>(tx_buf.size()) < len + 2)
					break;
				onFrame(tx_buf.data() + 2, len);
				tx_buf.erase(tx_buf.begin(), tx_buf.begin() + len + 2);
				if (((len + 2) % BULK_MPS) == 0)
				{
					if (!tx_buf.empty())
						tx_buf.erase(tx_buf.begin());
					else
						tx_pad_pending = true;
				}
			}
			return errors;
		}

		bool TxIdle() const { return tx_buf.empty(); }

		// Size of the bulk IN transfer for a frame of len bytes.
		static int RxSize(int len) { return (len < MIN_FRAME ? MIN_FRAME : len) + RX_OVERHEAD; }

		// Builds the bulk IN transfer for one received frame. out must hold RxSize(len).
		static int BuildRx(const uint8_t* frame, int len, uint8_t* out)
		{
			const int padded = len < MIN_FRAME ? MIN_FRAME : len;
			const int total = padded + RX_OVERHEAD;
			std::memset(out, 0, total);
			out[0] = static_cast<uint8_t>(total & 0xFF);
			out[1] = static_cast<uint8_t>(total >> 8);
			std::memcpy(out + 2, frame, len);
			// out[2 + padded .. +3] = CRC (not checked), out[total - 2] = status 0, out[total - 1] = 0
			return total;
		}

	private:
		std::vector<uint8_t> tx_buf;
		bool tx_pad_pending = false;
	};
} // namespace usb_namco_uenet
