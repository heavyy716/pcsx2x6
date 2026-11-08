// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "InputSyncProtocol.h"

#include <algorithm>
#include <charconv>
#include <cstring>

namespace InputSync
{
	namespace
	{
		class Writer
		{
		public:
			explicit Writer(PacketType type)
			{
				U32(PACKET_MAGIC);
				U8(static_cast<u8>(type));
			}

			void U8(u8 v) { m_buf.push_back(v); }
			void U16(u16 v)
			{
				U8(static_cast<u8>(v));
				U8(static_cast<u8>(v >> 8));
			}
			void U32(u32 v)
			{
				U16(static_cast<u16>(v));
				U16(static_cast<u16>(v >> 16));
			}
			void U64(u64 v)
			{
				U32(static_cast<u32>(v));
				U32(static_cast<u32>(v >> 32));
			}
			void Str(std::string_view s)
			{
				const size_t len = std::min<size_t>(s.size(), 255);
				U8(static_cast<u8>(len));
				m_buf.insert(m_buf.end(), s.begin(), s.begin() + len);
			}
			void Bytes(std::span<const u8> b)
			{
				U16(static_cast<u16>(b.size()));
				m_buf.insert(m_buf.end(), b.begin(), b.end());
			}
			std::vector<u8> Take() { return std::move(m_buf); }

		private:
			std::vector<u8> m_buf;
		};

		class Reader
		{
		public:
			Reader(std::span<const u8> data, PacketType type)
				: m_data(data)
			{
				if (U32() != PACKET_MAGIC || U8() != static_cast<u8>(type))
					m_ok = false;
			}

			bool Ok() const { return m_ok; }
			bool AtEnd() const { return m_ok && m_pos == m_data.size(); }

			u8 U8()
			{
				if (!m_ok || m_pos + 1 > m_data.size())
				{
					m_ok = false;
					return 0;
				}
				return m_data[m_pos++];
			}
			u16 U16()
			{
				const u16 lo = U8();
				return static_cast<u16>(lo | (static_cast<u16>(U8()) << 8));
			}
			u32 U32()
			{
				const u32 lo = U16();
				return lo | (static_cast<u32>(U16()) << 16);
			}
			u64 U64()
			{
				const u64 lo = U32();
				return lo | (static_cast<u64>(U32()) << 32);
			}
			std::string Str()
			{
				const size_t len = U8();
				if (!m_ok || m_pos + len > m_data.size())
				{
					m_ok = false;
					return {};
				}
				std::string ret(reinterpret_cast<const char*>(m_data.data() + m_pos), len);
				m_pos += len;
				return ret;
			}
			std::vector<u8> Bytes()
			{
				const size_t len = U16();
				if (!m_ok || m_pos + len > m_data.size())
				{
					m_ok = false;
					return {};
				}
				std::vector<u8> ret(m_data.begin() + m_pos, m_data.begin() + m_pos + len);
				m_pos += len;
				return ret;
			}

		private:
			std::span<const u8> m_data;
			size_t m_pos = 0;
			bool m_ok = true;
		};
	} // namespace

	PeerInput MakeLocalInput(const u16 live_buttons[2], const u8 live_coins[2], u8 live_test)
	{
		PeerInput ret;
		ret.buttons = static_cast<u16>(live_buttons[0] | live_buttons[1]);
		ret.coins = static_cast<u8>(std::min<u32>(static_cast<u32>(live_coins[0]) + live_coins[1], 0xFFu));
		ret.test = live_test;
		return ret;
	}

	FrameInput CombineInputs(u32 local_side, const PeerInput& local, const PeerInput& remote)
	{
		const u32 ls = local_side ? 1 : 0;
		FrameInput ret;
		ret.buttons[ls] = local.buttons;
		ret.coins[ls] = local.coins;
		ret.buttons[ls ^ 1] = remote.buttons;
		ret.coins[ls ^ 1] = remote.coins;
		ret.test = static_cast<u8>(local.test | remote.test);
		return ret;
	}

	std::vector<u8> Encode(const HelloMsg& msg)
	{
		Writer w(PacketType::Hello);
		w.U32(msg.protocol);
		w.Str(msg.build);
		w.Str(msg.game);
		w.U64(msg.media_hash);
		w.U64(msg.bios_hash);
		w.U64(msg.dongle_hash);
		w.U16(msg.dip_bits);
		return w.Take();
	}

	std::vector<u8> Encode(const WelcomeMsg& msg)
	{
		Writer w(PacketType::Welcome);
		w.U32(msg.session);
		w.U8(msg.client_side);
		w.U8(msg.delay);
		w.U16(msg.hash_interval);
		w.U32(msg.blob_size);
		w.U64(msg.blob_hash);
		w.U64(msg.settings_hash);
		w.U8(msg.warnings);
		return w.Take();
	}

	std::vector<u8> Encode(const RejectMsg& msg)
	{
		Writer w(PacketType::Reject);
		w.U8(static_cast<u8>(msg.reason));
		w.Str(msg.detail);
		return w.Take();
	}

	std::vector<u8> Encode(const ChunkMsg& msg)
	{
		Writer w(PacketType::Chunk);
		w.U32(msg.session);
		w.U32(msg.offset);
		w.U32(msg.total);
		w.Bytes(msg.data);
		return w.Take();
	}

	std::vector<u8> Encode(const ReadyMsg& msg)
	{
		Writer w(PacketType::Ready);
		w.U32(msg.session);
		w.U64(msg.blob_hash);
		return w.Take();
	}

	std::vector<u8> Encode(const InputMsg& msg)
	{
		Writer w(PacketType::Input);
		w.U32(msg.session);
		w.U32(msg.ack);
		w.U32(msg.first_frame);
		const size_t count = std::min<size_t>(msg.inputs.size(), MAX_INPUTS_PER_PACKET);
		w.U8(static_cast<u8>(count));
		for (size_t i = 0; i < count; i++)
		{
			w.U16(msg.inputs[i].buttons);
			w.U8(msg.inputs[i].coins);
			w.U8(msg.inputs[i].test);
		}
		w.U32(msg.hash_frame);
		w.U64(msg.hash);
		return w.Take();
	}

	std::vector<u8> EncodeSession(PacketType type, const SessionMsg& msg)
	{
		Writer w(type);
		w.U32(msg.session);
		return w.Take();
	}

	std::optional<PacketType> PeekType(std::span<const u8> packet)
	{
		if (packet.size() < 5)
			return std::nullopt;
		const u32 magic = static_cast<u32>(packet[0]) | (static_cast<u32>(packet[1]) << 8) |
						  (static_cast<u32>(packet[2]) << 16) | (static_cast<u32>(packet[3]) << 24);
		if (magic != PACKET_MAGIC)
			return std::nullopt;
		const u8 type = packet[4];
		if (type < static_cast<u8>(PacketType::Hello) || type > static_cast<u8>(PacketType::Bye))
			return std::nullopt;
		return static_cast<PacketType>(type);
	}

	bool Decode(std::span<const u8> packet, HelloMsg* msg)
	{
		Reader r(packet, PacketType::Hello);
		msg->protocol = r.U32();
		msg->build = r.Str();
		msg->game = r.Str();
		msg->media_hash = r.U64();
		msg->bios_hash = r.U64();
		msg->dongle_hash = r.U64();
		msg->dip_bits = r.U16();
		return r.AtEnd();
	}

	bool Decode(std::span<const u8> packet, WelcomeMsg* msg)
	{
		Reader r(packet, PacketType::Welcome);
		msg->session = r.U32();
		msg->client_side = r.U8();
		msg->delay = r.U8();
		msg->hash_interval = r.U16();
		msg->blob_size = r.U32();
		msg->blob_hash = r.U64();
		msg->settings_hash = r.U64();
		msg->warnings = r.U8();
		return r.AtEnd() && msg->client_side <= 1 && msg->delay <= MAX_DELAY;
	}

	bool Decode(std::span<const u8> packet, RejectMsg* msg)
	{
		Reader r(packet, PacketType::Reject);
		msg->reason = static_cast<RejectReason>(r.U8());
		msg->detail = r.Str();
		return r.AtEnd();
	}

	bool Decode(std::span<const u8> packet, ChunkMsg* msg)
	{
		Reader r(packet, PacketType::Chunk);
		msg->session = r.U32();
		msg->offset = r.U32();
		msg->total = r.U32();
		msg->data = r.Bytes();
		return r.AtEnd() && msg->offset <= msg->total && msg->data.size() <= msg->total - msg->offset;
	}

	bool Decode(std::span<const u8> packet, ReadyMsg* msg)
	{
		Reader r(packet, PacketType::Ready);
		msg->session = r.U32();
		msg->blob_hash = r.U64();
		return r.AtEnd();
	}

	bool Decode(std::span<const u8> packet, InputMsg* msg)
	{
		Reader r(packet, PacketType::Input);
		msg->session = r.U32();
		msg->ack = r.U32();
		msg->first_frame = r.U32();
		const u8 count = r.U8();
		if (count > MAX_INPUTS_PER_PACKET)
			return false;
		msg->inputs.resize(count);
		for (PeerInput& in : msg->inputs)
		{
			in.buttons = r.U16();
			in.coins = r.U8();
			in.test = r.U8();
		}
		msg->hash_frame = r.U32();
		msg->hash = r.U64();
		return r.AtEnd();
	}

	bool DecodeSession(std::span<const u8> packet, PacketType type, SessionMsg* msg)
	{
		Reader r(packet, type);
		msg->session = r.U32();
		return r.AtEnd();
	}

	const char* GetRejectReasonText(RejectReason reason)
	{
		switch (reason)
		{
			case RejectReason::Busy:
				return "The host is already playing with someone else.";
			case RejectReason::Protocol:
				return "The two PCSX2x6 versions use different netplay protocols. Use the same build on both PCs.";
			case RejectReason::Build:
				return "The two PCs run different PCSX2x6 builds. Use the same build on both PCs.";
			case RejectReason::Game:
				return "The two PCs are running different games.";
			case RejectReason::Media:
				return "The game files differ between the two PCs (different dump or version).";
			case RejectReason::Bios:
				return "The two PCs use different BIOS files. Use the same BIOS on both PCs.";
			default:
				return "The connection was refused.";
		}
	}

	void InputQueue::Reset(u32 base_frame)
	{
		m_base = base_frame;
		m_items.clear();
	}

	void InputQueue::Set(u32 frame, const PeerInput& input)
	{
		if (frame < m_base)
			return;
		const size_t idx = frame - m_base;
		if (idx >= 1u << 20) // garbage frame number, refuse to allocate
			return;
		if (idx >= m_items.size())
			m_items.resize(idx + 1);
		if (!m_items[idx].has_value())
			m_items[idx] = input;
	}

	bool InputQueue::Has(u32 frame) const
	{
		return Get(frame) != nullptr;
	}

	const PeerInput* InputQueue::Get(u32 frame) const
	{
		if (frame < m_base)
			return nullptr;
		const size_t idx = frame - m_base;
		if (idx >= m_items.size() || !m_items[idx].has_value())
			return nullptr;
		return &m_items[idx].value();
	}

	u32 InputQueue::ContiguousEnd() const
	{
		u32 frame = m_base;
		for (const std::optional<PeerInput>& item : m_items)
		{
			if (!item.has_value())
				break;
			frame++;
		}
		return frame;
	}

	void InputQueue::DiscardBefore(u32 frame)
	{
		while (m_base < frame && !m_items.empty() && m_items.front().has_value())
		{
			m_items.pop_front();
			m_base++;
		}
	}

	void DesyncTracker::Reset()
	{
		m_local.clear();
		m_remote.clear();
		m_first_desync.reset();
		m_matched = 0;
	}

	DesyncTracker::Result DesyncTracker::AddLocal(u32 frame, u64 hash)
	{
		m_local.emplace(frame, hash);
		return Check(frame);
	}

	DesyncTracker::Result DesyncTracker::AddRemote(u32 frame, u64 hash)
	{
		m_remote.emplace(frame, hash);
		return Check(frame);
	}

	DesyncTracker::Result DesyncTracker::Check(u32 frame)
	{
		const auto lit = m_local.find(frame);
		const auto rit = m_remote.find(frame);
		if (lit == m_local.end() || rit == m_remote.end())
			return Result::Pending;

		const bool match = (lit->second == rit->second);
		m_local.erase(m_local.begin(), std::next(lit));
		m_remote.erase(m_remote.begin(), std::next(rit));
		if (match)
		{
			m_matched++;
			return Result::Match;
		}

		if (!m_first_desync.has_value())
			m_first_desync = frame;
		return Result::Mismatch;
	}

	std::string NormalizeSettingsText(std::vector<std::string> lines)
	{
		std::sort(lines.begin(), lines.end());
		std::string ret;
		for (const std::string& line : lines)
		{
			ret += line;
			ret += '\n';
		}
		return ret;
	}

	std::vector<std::pair<std::string, std::string>> ParseSettingsText(std::string_view text)
	{
		std::vector<std::pair<std::string, std::string>> ret;
		while (!text.empty())
		{
			const size_t nl = text.find('\n');
			const std::string_view line = text.substr(0, nl);
			text = (nl == std::string_view::npos) ? std::string_view() : text.substr(nl + 1);
			const size_t eq = line.find('=');
			if (eq == std::string_view::npos || eq == 0)
				continue;
			ret.emplace_back(std::string(line.substr(0, eq)), std::string(line.substr(eq + 1)));
		}
		return ret;
	}

	bool ParseHostPort(std::string_view text, std::string* host, u16* port)
	{
		while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
			text.remove_prefix(1);
		while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
			text.remove_suffix(1);
		if (text.empty())
			return false;

		const size_t colon = text.rfind(':');
		if (colon == std::string_view::npos)
		{
			*host = std::string(text);
			*port = DEFAULT_PORT;
			return true;
		}
		if (text.find(':') != colon || colon == 0)
			return false;

		const std::string_view port_str = text.substr(colon + 1);
		u32 value = 0;
		const auto res = std::from_chars(port_str.data(), port_str.data() + port_str.size(), value);
		if (res.ec != std::errc() || res.ptr != port_str.data() + port_str.size() || value == 0 || value > 65535)
			return false;

		*host = std::string(text.substr(0, colon));
		*port = static_cast<u16>(value);
		return true;
	}

	static void PutU64(u8* p, u64 v)
	{
		for (int i = 0; i < 8; i++)
			p[i] = static_cast<u8>(v >> (i * 8));
	}

	static u64 GetU64(const u8* p)
	{
		u64 v = 0;
		for (int i = 0; i < 8; i++)
			v |= static_cast<u64>(p[i]) << (i * 8);
		return v;
	}

	static constexpr char RECORDING_MAGIC[8] = {'P', 'X', '6', 'I', 'N', 'R', 'E', 'C'};
	static constexpr u32 RECORDING_VERSION = 1;

	std::vector<u8> EncodeRecordingHeader(const RecordingHeader& hdr)
	{
		std::vector<u8> ret(RECORDING_HEADER_SIZE, 0);
		std::memcpy(ret.data(), RECORDING_MAGIC, sizeof(RECORDING_MAGIC));
		ret[8] = static_cast<u8>(RECORDING_VERSION);
		std::memcpy(&ret[16], hdr.game.data(), std::min<size_t>(hdr.game.size(), 16));
		PutU64(&ret[32], hdr.settings_hash);
		PutU64(&ret[40], hdr.sram_hash);
		PutU64(&ret[48], hdr.nvram_hash);
		return ret;
	}

	bool DecodeRecordingHeader(std::span<const u8> data, RecordingHeader* hdr)
	{
		if (data.size() < RECORDING_HEADER_SIZE || std::memcmp(data.data(), RECORDING_MAGIC, sizeof(RECORDING_MAGIC)) != 0 ||
			data[8] != RECORDING_VERSION)
			return false;
		const char* game = reinterpret_cast<const char*>(&data[16]);
		hdr->game.assign(game, strnlen(game, 16));
		hdr->settings_hash = GetU64(&data[32]);
		hdr->sram_hash = GetU64(&data[40]);
		hdr->nvram_hash = GetU64(&data[48]);
		return true;
	}

	void EncodeRecordingFrame(const FrameInput& in, u8 out[RECORDING_FRAME_SIZE])
	{
		out[0] = static_cast<u8>(in.buttons[0]);
		out[1] = static_cast<u8>(in.buttons[0] >> 8);
		out[2] = static_cast<u8>(in.buttons[1]);
		out[3] = static_cast<u8>(in.buttons[1] >> 8);
		out[4] = in.coins[0];
		out[5] = in.coins[1];
		out[6] = in.test;
		out[7] = 0;
	}

	FrameInput DecodeRecordingFrame(const u8 in[RECORDING_FRAME_SIZE])
	{
		FrameInput ret;
		ret.buttons[0] = static_cast<u16>(in[0] | (in[1] << 8));
		ret.buttons[1] = static_cast<u16>(in[2] | (in[3] << 8));
		ret.coins[0] = in[4];
		ret.coins[1] = in[5];
		ret.test = in[6];
		return ret;
	}
} // namespace InputSync
