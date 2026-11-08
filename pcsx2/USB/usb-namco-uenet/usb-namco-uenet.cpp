// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#include "USB/usb-namco-uenet/usb-namco-uenet.h"
#include "USB/usb-namco-uenet/uenet-model.h"
#include "USB/qemu-usb/qusb.h"
#include "USB/qemu-usb/desc.h"
#include "USB/qemu-usb/USBinternal.h"
#include "USB/USB.h"
#include "DEV9/LinkProbe.h"
#include "DEV9/vlan_link.h"
#include "common/Console.h"
#include "Host.h"
#include "IconsFontAwesome.h"
#include "StateWrapper.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace usb_namco_uenet
{
	static const uint8_t uenet_dev_descriptor[] = {
		0x12,       // bLength
		0x01,       // bDescriptorType (Device)
		0x10, 0x01, // bcdUSB 1.10
		0x00,       // bDeviceClass (per interface)
		0x00,       // bDeviceSubClass
		0x00,       // bDeviceProtocol
		0x08,       // bMaxPacketSize0 8
		0x9A, 0x0B, // idVendor 0x0B9A (Namco)
		0x00, 0x05, // idProduct 0x0500 (System246 UE PCB)
		0x01, 0x01, // bcdDevice 1.01
		0x01,       // iManufacturer
		0x02,       // iProduct
		0x00,       // iSerialNumber
		0x01,       // bNumConfigurations
	};

	static const uint8_t uenet_config_descriptor[] = {
		0x09,       // bLength
		0x02,       // bDescriptorType (Configuration)
		0x27, 0x00, // wTotalLength 39
		0x01,       // bNumInterfaces (AN986 requires 1)
		0x01,       // bConfigurationValue
		0x00,       // iConfiguration
		0x80,       // bmAttributes (bus powered)
		0x32,       // bMaxPower 100mA

		0x09,       // bLength
		0x04,       // bDescriptorType (Interface)
		0x00,       // bInterfaceNumber
		0x00,       // bAlternateSetting
		0x03,       // bNumEndpoints (AN986 requires 3: bulk IN, bulk OUT, interrupt IN)
		0xFF,       // bInterfaceClass (vendor)
		0x00,       // bInterfaceSubClass
		0x00,       // bInterfaceProtocol
		0x00,       // iInterface

		0x07, 0x05, 0x81, 0x02, 0x40, 0x00, 0x00, // EP1 IN bulk 64
		0x07, 0x05, 0x02, 0x02, 0x40, 0x00, 0x00, // EP2 OUT bulk 64
		0x07, 0x05, 0x83, 0x03, 0x08, 0x00, 0x01, // EP3 IN interrupt 8, 1ms
	};

	static const USBDescStrings uenet_strings = {"", "namco", "System246 UE PCB"};

	static constexpr u8 VENDOR_GET_REGS = 0xF0;
	static constexpr u8 VENDOR_SET_REGS = 0xF1;
	static constexpr size_t RX_QUEUE_MAX = 64;

	struct UeNetState
	{
		USBDevice dev{};
		USBDesc desc{};
		USBDescDevice desc_dev{};

		u32 port = 0;
		UeNetModel model;
		u8 mac[6] = {};
		VlanLink link;
		std::deque<std::vector<u8>> rxq;
		std::unordered_map<u64, u64> hits;
		u64 tx_frames = 0;
		u64 rx_frames = 0;
		u64 rx_dropped = 0;
		bool noted_foreign_dst = false;
		bool noted_intr = false;
	};

	// LinkProbe-style dedup: the first four hits of a key and every power-of-two hit.
	static bool ShouldLog(UeNetState* s, u64 key, u64* count)
	{
		const u64 hit = ++s->hits[key];
		*count = hit;
		return hit <= 4 || (hit & (hit - 1)) == 0;
	}

	static void FormatBytes(char* out, size_t cap, const u8* d, int n)
	{
		size_t pos = 0;
		out[0] = 0;
		for (int i = 0; i < n && pos + 4 < cap; i++)
			pos += std::snprintf(out + pos, cap - pos, "%s%02X", i ? " " : "", d[i]);
		if (n > 0 && pos + 4 >= cap)
			std::snprintf(out + cap - 4, 4, "...");
	}

	static void NoteModelEvent(UeNetState* s)
	{
		const UeNetModel::LastOp op = s->model.last;
		s->model.last = {};
		u64 hit;
		switch (op.ev)
		{
			case UeNetModel::Event::EepromRead:
			case UeNetModel::Event::EepromWrite:
			{
				const bool rd = op.ev == UeNetModel::Event::EepromRead;
				if (ShouldLog(s, (0xEEull << 40) | (rd ? 0 : 0x100) | static_cast<u64>(op.addr), &hit))
					LinkProbe::Note("UENET EEPROM %s word %02X = %04X (hit %llu)", rd ? "read" : "write", op.addr, op.value,
						static_cast<unsigned long long>(hit));
				break;
			}
			case UeNetModel::Event::PhyRead:
			case UeNetModel::Event::PhyWrite:
			{
				const bool rd = op.ev == UeNetModel::Event::PhyRead;
				if (ShouldLog(s, (0xFEull << 40) | (rd ? 0 : 0x10000) | (static_cast<u64>(op.addr) << 8) | static_cast<u64>(op.reg), &hit))
					LinkProbe::Note("UENET PHY %s addr %d reg %d = %04X (hit %llu)", rd ? "read" : "write", op.addr, op.reg, op.value,
						static_cast<unsigned long long>(hit));
				break;
			}
			case UeNetModel::Event::MacReset:
				if (ShouldLog(s, 0xACull << 40, &hit))
					LinkProbe::Note("UENET MAC reset (EthCtrl1 %02X, self-cleared) (hit %llu)", op.value,
						static_cast<unsigned long long>(hit));
				break;
			case UeNetModel::Event::None:
				break;
		}
	}

	static void CheckMacChange(UeNetState* s)
	{
		u8 now[6];
		s->model.GetMac(now);
		if (std::memcmp(now, s->mac, 6) == 0)
			return;
		std::memcpy(s->mac, now, 6);
		LinkProbe::Note("UENET station address set to %02x:%02x:%02x:%02x:%02x:%02x", now[0], now[1], now[2], now[3], now[4], now[5]);
		s->link.SetMac(now);
	}

	static void PollLink(UeNetState* s)
	{
		if (!s->link.IsOpen())
			return;
		u8 buf[2048];
		for (int i = 0; i < 16; i++)
		{
			const int got = s->link.Recv(buf, sizeof(buf));
			if (got <= 0)
				return;
			if (std::memcmp(buf + 6, s->mac, 6) == 0)
				continue; // our own echo
			if (got > UeNetModel::MAX_TX_FRAME)
			{
				s->rx_dropped++;
				continue;
			}
			if (!s->model.RxEnabled())
			{
				s->rx_dropped++;
				if (s->rx_dropped == 1)
					LinkProbe::Note("UENET RX before the driver enabled the MAC (reg 00 = 0); dropping");
				continue;
			}
			const bool group = (buf[0] & 1) != 0;
			if (!group && std::memcmp(buf, s->mac, 6) != 0 && !s->noted_foreign_dst)
			{
				s->noted_foreign_dst = true;
				LinkProbe::Note("UENET unicast for %02x:%02x:%02x:%02x:%02x:%02x (not our MAC) delivered anyway",
					buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
			}
			if (s->rxq.size() >= RX_QUEUE_MAX)
			{
				s->rxq.pop_front();
				s->rx_dropped++;
			}
			s->rxq.emplace_back(buf, buf + got);
		}
	}

	static void uenet_handle_reset(USBDevice* dev)
	{
		UeNetState* s = USB_CONTAINER_OF(dev, UeNetState, dev);
		s->model.Reset();
		s->model.GetMac(s->mac);
		s->rxq.clear();
		LinkProbe::Note("UENET bus reset (port %u)", s->port);
	}

	static void uenet_handle_control(USBDevice* dev, USBPacket* p, int request, int value,
		int index, int length, uint8_t* data)
	{
		UeNetState* s = USB_CONTAINER_OF(dev, UeNetState, dev);
		u64 hit;

		const int ret = usb_desc_handle_control(dev, p, request, value, index, length, data);
		if (ret >= 0)
		{
			if (ShouldLog(s, (0x5Dull << 40) | (static_cast<u64>(request & 0xFFFF) << 16) | static_cast<u64>(value & 0xFFFF), &hit))
				LinkProbe::Note("UENET std request %04X value %04X index %04X len %d (hit %llu)", request & 0xFFFF, value & 0xFFFF,
					index & 0xFFFF, length, static_cast<unsigned long long>(hit));
			if (request == (DeviceOutRequest | USB_REQ_SET_CONFIGURATION))
			{
				LinkProbe::Note("UENET SET_CONFIGURATION %d", value);
				Console.WriteLn(Color_StrongGreen, "USB: Namco UE PCB configured (config %d)", value);
			}
			return;
		}

		switch (request)
		{
			case VendorDeviceRequest | VENDOR_GET_REGS:
			{
				const int n = std::min(length, 256);
				s->model.ReadRegs(index, data, n);
				p->actual_length = n;
				if (ShouldLog(s, (0xF0ull << 40) | (static_cast<u64>(index & 0xFF) << 16) | static_cast<u64>(n), &hit))
				{
					char hex[64];
					FormatBytes(hex, sizeof(hex), data, n);
					LinkProbe::Note("UENET get reg %02X len %d -> %s (hit %llu)", index & 0xFF, n, hex, static_cast<unsigned long long>(hit));
				}
				break;
			}
			case VendorDeviceOutRequest | VENDOR_SET_REGS:
			{
				u8 single = static_cast<u8>(value & 0xFF);
				const u8* src = length > 0 ? data : &single;
				const int n = length > 0 ? std::min(length, 256) : 1;
				if (ShouldLog(s, (0xF1ull << 40) | (static_cast<u64>(index & 0xFF) << 16) | static_cast<u64>(n), &hit))
				{
					char hex[64];
					FormatBytes(hex, sizeof(hex), src, n);
					LinkProbe::Note("UENET set reg %02X len %d <- %s (hit %llu)", index & 0xFF, n, hex, static_cast<unsigned long long>(hit));
				}
				s->model.WriteRegs(index, src, n);
				NoteModelEvent(s);
				CheckMacChange(s);
				break;
			}
			default:
				LinkProbe::Note("UENET unhandled control request %04X value %04X index %04X len %d: STALL", request & 0xFFFF,
					value & 0xFFFF, index & 0xFFFF, length);
				p->status = USB_RET_STALL;
				break;
		}
	}

	static void uenet_handle_data(USBDevice* dev, USBPacket* p)
	{
		UeNetState* s = USB_CONTAINER_OF(dev, UeNetState, dev);
		const int ep = p->ep->nr;

		if (p->pid == USB_TOKEN_OUT && ep == 2)
		{
			const int n = static_cast<int>(p->buffer_size);
			std::vector<u8> chunk(n);
			if (n > 0)
				usb_packet_copy(p, chunk.data(), n);
			const int errors = s->model.FeedTx(chunk.data(), n, [s](const u8* frame, int len) {
				s->tx_frames++;
				LinkProbe::Frame("TX(usb)", frame, len);
				s->link.Send(frame, len);
			});
			if (errors)
			{
				char hex[64];
				FormatBytes(hex, sizeof(hex), chunk.data(), std::min(n, 16));
				LinkProbe::Note("UENET TX framing error, dropped buffered data (packet %d bytes: %s)", n, hex);
			}
			return;
		}

		if (p->pid == USB_TOKEN_IN && ep == 1)
		{
			PollLink(s);
			if (s->rxq.empty())
			{
				p->status = USB_RET_NAK;
				return;
			}
			const std::vector<u8> frame = std::move(s->rxq.front());
			s->rxq.pop_front();
			std::vector<u8> out(UeNetModel::RxSize(static_cast<int>(frame.size())));
			const int total = UeNetModel::BuildRx(frame.data(), static_cast<int>(frame.size()), out.data());
			const int cap = static_cast<int>(p->buffer_size);
			if (total > cap)
				LinkProbe::Note("UENET RX transfer %d bytes truncated to the %d-byte IN buffer", total, cap);
			s->rx_frames++;
			LinkProbe::Frame("RX(usb)", frame.data(), static_cast<int>(frame.size()));
			usb_packet_copy(p, out.data(), std::min(total, cap));
			return;
		}

		if (p->pid == USB_TOKEN_IN && ep == 3)
		{
			if (!s->noted_intr)
			{
				s->noted_intr = true;
				LinkProbe::Note("UENET interrupt endpoint polled (NAK; link status is static)");
			}
			p->status = USB_RET_NAK;
			return;
		}

		LinkProbe::Note("UENET unexpected %s on endpoint %d: STALL", p->pid == USB_TOKEN_IN ? "IN" : "OUT", ep);
		p->status = USB_RET_STALL;
	}

	static void uenet_handle_destroy(USBDevice* dev)
	{
		UeNetState* s = USB_CONTAINER_OF(dev, UeNetState, dev);
		LinkProbe::Note("UENET detached: %llu TX frames, %llu RX frames, %llu RX dropped",
			static_cast<unsigned long long>(s->tx_frames), static_cast<unsigned long long>(s->rx_frames),
			static_cast<unsigned long long>(s->rx_dropped));
		s->link.Close();
		delete s;
	}

	USBDevice* UeNetDevice::CreateDevice(SettingsInterface& si, u32 port, u32 subtype) const
	{
		LinkProbe::Init();

		UeNetState* s = new UeNetState();
		s->port = port;

		// Locally administered default, distinct per USB port.
		u8 mac[6] = {0x02, 0x00, 0x0B, 0x9A, 0x05, static_cast<u8>(0x01 + port)};
		const std::string macStr = VlanLink::GetEnv("PCSX2X6_VLAN_MAC");
		if (!macStr.empty() && !VlanLink::ParseMac(macStr, mac))
			Console.Error("USB: Namco UE PCB: ignoring malformed PCSX2X6_VLAN_MAC='%s'", macStr.c_str());
		s->model.Init(mac);
		std::memcpy(s->mac, mac, 6);

		s->dev.speed = USB_SPEED_FULL;
		s->desc.full = &s->desc_dev;
		s->desc.str = uenet_strings;
		if (usb_desc_parse_dev(uenet_dev_descriptor, sizeof(uenet_dev_descriptor), s->desc, s->desc_dev) < 0)
			goto fail;
		if (usb_desc_parse_config(uenet_config_descriptor, sizeof(uenet_config_descriptor), s->desc_dev) < 0)
			goto fail;

		s->dev.klass.handle_attach = usb_desc_attach;
		s->dev.klass.handle_reset = uenet_handle_reset;
		s->dev.klass.handle_control = uenet_handle_control;
		s->dev.klass.handle_data = uenet_handle_data;
		s->dev.klass.unrealize = uenet_handle_destroy;
		s->dev.klass.usb_desc = &s->desc;
		s->dev.klass.product_desc = s->desc.str[2];

		usb_desc_init(&s->dev);
		usb_ep_init(&s->dev);
		uenet_handle_reset(&s->dev);

		{
			const std::string target = VlanLink::GetEnv("PCSX2X6_VLAN");
			if (!target.empty())
				s->link.Open(target, mac, "USB");
			else
				Console.Warning("USB: Namco UE PCB attached without PCSX2X6_VLAN; frames are only logged");
		}
		LinkProbe::Note("UENET attached: USB port %u, 0B9A:0500 'System246 UE PCB', mac=%02x:%02x:%02x:%02x:%02x:%02x, vlan=%s",
			port, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], s->link.IsOpen() ? s->link.Target().c_str() : "(none)");
		return &s->dev;

	fail:
		uenet_handle_destroy(&s->dev);
		return nullptr;
	}

	const char* UeNetDevice::Name() const
	{
		return TRANSLATE_NOOP("USB", "Namco System246 UE PCB (USB LAN)");
	}

	const char* UeNetDevice::TypeName() const
	{
		return "namco_uenet";
	}

	const char* UeNetDevice::IconName() const
	{
		return ICON_FA_NETWORK_WIRED;
	}

	bool UeNetDevice::Freeze(USBDevice* dev, StateWrapper& sw) const
	{
		UeNetState* s = USB_CONTAINER_OF(dev, UeNetState, dev);
		if (!sw.DoMarker("NamcoUeNet"))
			return false;
		sw.DoBytes(s->model.regs, sizeof(s->model.regs));
		sw.DoBytes(s->model.eeprom, sizeof(s->model.eeprom));
		sw.DoBytes(s->model.phy, sizeof(s->model.phy));
		if (sw.IsReading())
		{
			s->model.GetMac(s->mac);
			s->rxq.clear();
		}
		return !sw.HasError();
	}
} // namespace usb_namco_uenet
