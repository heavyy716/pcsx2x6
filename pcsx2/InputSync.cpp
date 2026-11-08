// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "InputSync.h"
#include "InputSyncProtocol.h"

#include "BuildVersion.h"
#include "CDVD/CDVD.h"
#include "Config.h"
#include "DEV9/ACJV.h"
#include "DEV9/ACSRAM.h"
#include "Host.h"
#include "MemoryTypes.h"
#include "VMManager.h"

#include "common/Console.h"
#include "common/Error.h"
#include "common/FileSystem.h"
#include "common/MemorySettingsInterface.h"
#include "common/SettingsWrapper.h"
#include "common/Timer.h"

#include "IconsFontAwesome.h"
#include "fmt/format.h"
#define XXH_INLINE_ALL 1
#include "xxhash.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <random>
#include <vector>

#ifdef _WIN32
#include "common/RedtapeWindows.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
using socket_t = SOCKET;
static constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t INVALID_SOCK = -1;
#endif

namespace InputSync
{
	namespace
	{
		struct Session
		{
			Options opts;

			// netplay
			socket_t sock = INVALID_SOCK;
			sockaddr_in peer = {};
			bool peer_known = false;
			u32 session_id = 0;
			u32 local_side = 0;
			u32 delay = DEFAULT_DELAY;
			u32 hash_interval = DEFAULT_HASH_INTERVAL;
			InputQueue local_q;
			InputQueue remote_q;
			u32 remote_ack = 0;
			bool disconnected = false;
			bool host_peer_ready = false;
			std::vector<u8> blob; // host: NVRAM + SRAM + settings, sent to the client
			u64 blob_hash = 0;
			u8 warnings = 0;
			DesyncTracker desync;
			u32 last_remote_hash_frame = 0xFFFFFFFFu;
			u32 last_hash_frame = 0xFFFFFFFFu;
			u64 last_hash = 0;
			Common::Timer::Value last_send = 0;
			Common::Timer::Value last_recv = 0;
			bool got_remote_input = false;

			// record/replay
			std::FILE* record_fp = nullptr;
			std::vector<u8> replay;
			size_t replay_frames = 0;

			std::FILE* hash_log = nullptr;
			u32 frame = 0;
			bool shutdown_requested = false;
			bool startup_messages_shown = false;
			std::string startup_warning;
		};

		static std::mutex s_pending_mutex;
		static std::optional<Options> s_pending;
		static std::atomic<Mode> s_mode{Mode::Off};
		static std::atomic<bool> s_cancel{false};
		static Session s;

		// Settings copied from the host (client) / settings expected by the recording (replay).
		static std::string s_remote_settings_text;
		static u64 s_expected_settings_hash = 0;
		static bool s_settings_mismatch = false;
		static std::string s_local_settings_text;

		static constexpr const char* SYNCED_SECTIONS[] = {
			"EmuCore/CPU",
			"EmuCore/CPU/Recompiler",
			"EmuCore/Gamefixes",
			"EmuCore/Speedhacks",
		};
		static constexpr const char* SYNCED_CORE_KEYS[] = {
			"EnableGameFixes",
			"EnableNoInterlacingPatches",
			"EnablePatches",
			"EnableWideScreenPatches",
		};
		static constexpr const char* OSD_KEY = "InputSync";
		static constexpr const char* OSD_DESYNC_KEY = "InputSyncDesync";
	} // namespace

	static u64 HashBytes(const void* data, size_t size, u64 seed = 0)
	{
		return XXH3_64bits_withSeed(data, size, seed);
	}

	static u64 HashString(std::string_view str)
	{
		return HashBytes(str.data(), str.size());
	}

	static bool ReadCoreBool(const char* key)
	{
		if (std::strcmp(key, "EnableGameFixes") == 0)
			return EmuConfig.EnableGameFixes;
		if (std::strcmp(key, "EnableNoInterlacingPatches") == 0)
			return EmuConfig.EnableNoInterlacingPatches;
		if (std::strcmp(key, "EnablePatches") == 0)
			return EmuConfig.EnablePatches;
		if (std::strcmp(key, "EnableWideScreenPatches") == 0)
			return EmuConfig.EnableWideScreenPatches;
		return false;
	}

	static void WriteCoreBool(const char* key, bool value)
	{
		if (std::strcmp(key, "EnableGameFixes") == 0)
			EmuConfig.EnableGameFixes = value;
		else if (std::strcmp(key, "EnableNoInterlacingPatches") == 0)
			EmuConfig.EnableNoInterlacingPatches = value;
		else if (std::strcmp(key, "EnablePatches") == 0)
			EmuConfig.EnablePatches = value;
		else if (std::strcmp(key, "EnableWideScreenPatches") == 0)
			EmuConfig.EnableWideScreenPatches = value;
	}

	// Determinism-relevant settings of the current EmuConfig as sorted "section/key=value" lines.
	static std::string BuildSettingsText()
	{
		MemorySettingsInterface msi;
		{
			SettingsSaveWrapper sw(msi);
			EmuConfig.Cpu.LoadSave(sw);
			EmuConfig.Speedhacks.LoadSave(sw);
			EmuConfig.Gamefixes.LoadSave(sw);
		}

		std::vector<std::string> lines;
		for (const char* section : SYNCED_SECTIONS)
		{
			for (const auto& [key, value] : msi.GetKeyValueList(section))
				lines.push_back(fmt::format("{}/{}={}", section, key, value));
		}
		for (const char* key : SYNCED_CORE_KEYS)
			lines.push_back(fmt::format("EmuCore/{}={}", key, ReadCoreBool(key) ? "true" : "false"));
		return NormalizeSettingsText(std::move(lines));
	}

	static void ApplySettingsText(std::string_view text)
	{
		MemorySettingsInterface msi;
		{
			// Start from the local values so anything the host didn't send keeps a sane value.
			SettingsSaveWrapper sw(msi);
			EmuConfig.Cpu.LoadSave(sw);
			EmuConfig.Speedhacks.LoadSave(sw);
			EmuConfig.Gamefixes.LoadSave(sw);
		}

		for (const auto& [path, value] : ParseSettingsText(text))
		{
			const size_t slash = path.rfind('/');
			if (slash == std::string::npos)
				continue;
			const std::string section = path.substr(0, slash);
			const std::string key = path.substr(slash + 1);
			if (section == "EmuCore")
			{
				WriteCoreBool(key.c_str(), value == "true");
				continue;
			}
			msi.SetStringValue(section.c_str(), key.c_str(), value.c_str());
		}

		SettingsLoadWrapper lw(msi);
		EmuConfig.Cpu.LoadSave(lw);
		EmuConfig.Speedhacks.LoadSave(lw);
		EmuConfig.Gamefixes.LoadSave(lw);
	}

	void SetPendingOptions(const Options& options)
	{
		std::unique_lock lock(s_pending_mutex);
		if (options.mode == Mode::Off)
			s_pending.reset();
		else
			s_pending = options;
	}

	bool HasPendingOptions()
	{
		std::unique_lock lock(s_pending_mutex);
		return s_pending.has_value();
	}

	void ClearPendingOptions()
	{
		std::unique_lock lock(s_pending_mutex);
		s_pending.reset();
	}

	void Prepare()
	{
		EndSession();

		std::optional<Options> opts;
		{
			std::unique_lock lock(s_pending_mutex);
			opts = std::move(s_pending);
			s_pending.reset();
		}
		if (!opts.has_value() || opts->mode == Mode::Off)
			return;

		s.opts = std::move(opts.value());
		s.opts.delay = std::min<u32>(s.opts.delay, MAX_DELAY);
		if (s.opts.hash_interval == 0)
			s.opts.hash_interval = DEFAULT_HASH_INTERVAL;
		s_remote_settings_text.clear();
		s_local_settings_text.clear();
		s_expected_settings_hash = 0;
		s_settings_mismatch = false;
		s_cancel.store(false, std::memory_order_release);
		s_mode.store(s.opts.mode, std::memory_order_release);
		Console.WriteLnFmt(Color_StrongGreen, "InputSync: session requested (mode {})", static_cast<int>(s.opts.mode));
	}

	bool IsActive()
	{
		return s_mode.load(std::memory_order_acquire) != Mode::Off;
	}

	bool IsNetplay()
	{
		const Mode mode = s_mode.load(std::memory_order_acquire);
		return mode == Mode::Host || mode == Mode::Join;
	}

	Mode GetMode()
	{
		return s_mode.load(std::memory_order_acquire);
	}

	void CancelConnect()
	{
		s_cancel.store(true, std::memory_order_release);
	}

	void ApplyCoreSettingOverrides(SettingsInterface& si)
	{
		(void)si;
		if (!IsActive())
			return;

		if (!s_remote_settings_text.empty())
			ApplySettingsText(s_remote_settings_text);

		// Multi-threaded VU1 and cheats can make the two sides (or two replays) drift apart.
		EmuConfig.Speedhacks.vuThread = false;
		EmuConfig.EnableCheats = false;

		s_local_settings_text = BuildSettingsText();
		if (s_expected_settings_hash != 0 && HashString(s_local_settings_text) != s_expected_settings_hash)
		{
			if (!s_settings_mismatch)
				Console.Warning("InputSync: emulation settings differ from the other side/recording.");
			s_settings_mismatch = true;
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// Sockets
	//////////////////////////////////////////////////////////////////////////

	static bool s_wsa_started = false;

	static void CloseSocket()
	{
		if (s.sock == INVALID_SOCK)
			return;
#ifdef _WIN32
		closesocket(s.sock);
#else
		close(s.sock);
#endif
		s.sock = INVALID_SOCK;
	}

	static bool OpenSocket(u16 bind_port, Error* error)
	{
#ifdef _WIN32
		if (!s_wsa_started)
		{
			WSADATA wsa;
			if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
			{
				Error::SetString(error, "Could not start networking (WSAStartup failed).");
				return false;
			}
			s_wsa_started = true;
		}
#endif

		s.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s.sock == INVALID_SOCK)
		{
			Error::SetString(error, "Could not create a network socket.");
			return false;
		}

#ifdef _WIN32
		// Don't let an ICMP "port unreachable" (peer not started yet) break the socket.
		BOOL connreset = FALSE;
		DWORD bytes = 0;
		WSAIoctl(s.sock, SIO_UDP_CONNRESET, &connreset, sizeof(connreset), nullptr, 0, &bytes, nullptr, nullptr);
		u_long nonblock = 1;
		ioctlsocket(s.sock, FIONBIO, &nonblock);
#else
		fcntl(s.sock, F_SETFL, fcntl(s.sock, F_GETFL, 0) | O_NONBLOCK);
#endif

		if (bind_port != 0)
		{
			int reuse = 1;
			setsockopt(s.sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
		}

		sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(bind_port);
		if (bind(s.sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
		{
			Error::SetStringFmt(error,
				"Could not use UDP port {}. Another program (or another copy of PCSX2x6) may already be using it.", bind_port);
			CloseSocket();
			return false;
		}
		return true;
	}

	static bool ResolveAddress(const std::string& host, u16 port, sockaddr_in* out)
	{
		*out = {};
		out->sin_family = AF_INET;
		out->sin_port = htons(port);
		if (inet_pton(AF_INET, host.c_str(), &out->sin_addr) == 1)
			return true;

		addrinfo hints = {};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		addrinfo* res = nullptr;
		if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
			return false;
		out->sin_addr = reinterpret_cast<const sockaddr_in*>(res->ai_addr)->sin_addr;
		freeaddrinfo(res);
		return true;
	}

	static void SendTo(const sockaddr_in& to, const std::vector<u8>& data)
	{
		if (s.sock == INVALID_SOCK)
			return;
		sendto(s.sock, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0,
			reinterpret_cast<const sockaddr*>(&to), sizeof(to));
	}

	static void SendToPeer(const std::vector<u8>& data)
	{
		if (s.peer_known)
			SendTo(s.peer, data);
	}

	// Returns packet size, 0 if nothing is waiting.
	static size_t Receive(u8* buf, size_t size, sockaddr_in* from)
	{
		if (s.sock == INVALID_SOCK)
			return 0;
		for (;;)
		{
#ifdef _WIN32
			int fromlen = sizeof(*from);
#else
			socklen_t fromlen = sizeof(*from);
#endif
			const auto ret = recvfrom(s.sock, reinterpret_cast<char*>(buf), static_cast<int>(size), 0,
				reinterpret_cast<sockaddr*>(from), &fromlen);
			if (ret > 0)
				return static_cast<size_t>(ret);
			if (ret == 0)
				continue;
#ifdef _WIN32
			const int err = WSAGetLastError();
			if (err == WSAECONNRESET || err == WSAEMSGSIZE)
				continue;
#else
			if (errno == EINTR || errno == ECONNREFUSED)
				continue;
#endif
			return 0;
		}
	}

	static void WaitReadable(u32 timeout_ms)
	{
		if (s.sock == INVALID_SOCK)
			return;
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s.sock, &set);
		timeval tv;
		tv.tv_sec = static_cast<long>(timeout_ms / 1000);
		tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
		select(static_cast<int>(s.sock + 1), &set, nullptr, nullptr, &tv);
	}

	static bool SameAddress(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
	}

	static std::string AddressToString(const sockaddr_in& addr)
	{
		char buf[INET_ADDRSTRLEN] = {};
		inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
		return fmt::format("{}:{}", buf, ntohs(addr.sin_port));
	}

	static double MillisecondsSince(Common::Timer::Value start)
	{
		return Common::Timer::ConvertValueToMilliseconds(Common::Timer::GetCurrentValue() - start);
	}

	//////////////////////////////////////////////////////////////////////////
	// Hashes
	//////////////////////////////////////////////////////////////////////////

	static u64 ComputeStateHash()
	{
		u64 h = 0;
		h = HashBytes(eeMem->Main, Ps2MemSize::ExposedRam, h);
		h = HashBytes(eeMem->Scratch, Ps2MemSize::Scratch, h);
		h = HashBytes(iopMem->Main, Ps2MemSize::ExposedIopRam, h);
		h = HashBytes(ACSRAM::buffer, ACSRAM_MAX_SIZE, h);
		h = HashBytes(ACJV::coin, sizeof(ACJV::coin), h);
		return h;
	}

	static u64 ComputeMediaHash(const SessionInfo& info)
	{
		u64 h = HashString(info.game_id);
		h = HashBytes(&info.media_size, sizeof(info.media_size), h);
		if (!info.elf_path.empty())
		{
			if (std::optional<std::vector<u8>> elf = FileSystem::ReadBinaryFile(info.elf_path.c_str()); elf.has_value())
				h = HashBytes(elf->data(), elf->size(), h);
		}
		return h;
	}

	static u64 ComputeFileHash(const std::string& path)
	{
		if (path.empty())
			return 0;
		std::optional<std::vector<u8>> data = FileSystem::ReadBinaryFile(path.c_str());
		return data.has_value() ? HashBytes(data->data(), data->size()) : 0;
	}

	static std::string GetBuildId()
	{
		return fmt::format("{} {}", BuildVersion::GitRev, BuildVersion::GitHash);
	}

	static HelloMsg MakeHello(const SessionInfo& info)
	{
		HelloMsg hello;
		hello.build = GetBuildId();
		hello.game = info.game_id;
		hello.media_hash = ComputeMediaHash(info);
		hello.bios_hash = HashBytes(eeMem->ROM, Ps2MemSize::Rom);
		hello.dongle_hash = ComputeFileHash(info.dongle_path);
		hello.dip_bits = static_cast<u16>(ACJV::GetDIPSwitchBits() & ~static_cast<u16>(DIPS::TESTMODE));
		return hello;
	}

	//////////////////////////////////////////////////////////////////////////
	// Lockstep
	//////////////////////////////////////////////////////////////////////////

	static void ShowMessage(const char* key, const std::string& msg, float duration = Host::OSD_WARNING_DURATION)
	{
		Console.WarningFmt("InputSync: {}", msg);
		Host::AddIconOSDMessage(key, ICON_FA_TRIANGLE_EXCLAMATION, msg, duration);
	}

	static void MarkDisconnected(const std::string& why)
	{
		if (s.disconnected)
			return;
		s.disconnected = true;
		ShowMessage(OSD_KEY, fmt::format("{} The game continues, but the other player's controls no longer work.", why));
	}

	static void SendInputs()
	{
		InputMsg msg;
		msg.session = s.session_id;
		msg.ack = s.remote_q.ContiguousEnd();
		msg.first_frame = std::max(s.remote_ack, s.local_q.GetBase());
		const u32 end = s.local_q.ContiguousEnd();
		for (u32 f = msg.first_frame; f < end && msg.inputs.size() < MAX_INPUTS_PER_PACKET; f++)
			msg.inputs.push_back(*s.local_q.Get(f));
		msg.hash_frame = s.last_hash_frame;
		msg.hash = s.last_hash;
		SendToPeer(Encode(msg));
		s.last_send = Common::Timer::GetCurrentValue();
	}

	static void OnDesyncResult(DesyncTracker::Result result, u32 frame)
	{
		if (result != DesyncTracker::Result::Mismatch)
			return;
		if (s.desync.GetFirstDesyncFrame() != frame)
			return;
		ShowMessage(OSD_DESYNC_KEY,
			fmt::format("Desync detected (frame {}): the two games no longer match. Restart the match on both PCs.", frame),
			30.0f);
	}

	static void HandleInputMsg(const InputMsg& msg)
	{
		if (!msg.inputs.empty())
			s.got_remote_input = true;
		for (size_t i = 0; i < msg.inputs.size(); i++)
			s.remote_q.Set(msg.first_frame + static_cast<u32>(i), msg.inputs[i]);
		s.remote_ack = std::max(s.remote_ack, msg.ack);
		if (msg.hash_frame != 0xFFFFFFFFu && msg.hash_frame != s.last_remote_hash_frame)
		{
			s.last_remote_hash_frame = msg.hash_frame;
			OnDesyncResult(s.desync.AddRemote(msg.hash_frame, msg.hash), msg.hash_frame);
		}
	}

	// Handles packets during gameplay.
	static void ReceiveAll()
	{
		u8 buf[2048];
		sockaddr_in from;
		size_t len;
		while ((len = Receive(buf, sizeof(buf), &from)) > 0)
		{
			const std::span<const u8> pkt(buf, len);
			const std::optional<PacketType> type = PeekType(pkt);
			if (!type.has_value())
				continue;

			if (!SameAddress(from, s.peer))
			{
				// Someone else knocking while we're playing.
				if (type == PacketType::Hello && s.opts.mode == Mode::Host)
					SendTo(from, Encode(RejectMsg{RejectReason::Busy, {}}));
				continue;
			}

			s.last_recv = Common::Timer::GetCurrentValue();
			switch (type.value())
			{
				case PacketType::Input:
				{
					InputMsg msg;
					if (Decode(pkt, &msg) && msg.session == s.session_id)
					{
						s.host_peer_ready = true;
						HandleInputMsg(msg);
					}
				}
				break;

				case PacketType::Welcome:
				case PacketType::Chunk:
				{
					// Host is still resending setup data; our READY was lost.
					if (s.opts.mode == Mode::Join)
						SendToPeer(Encode(ReadyMsg{s.session_id, s.blob_hash}));
				}
				break;

				case PacketType::Ready:
					s.host_peer_ready = true;
					break;

				case PacketType::Bye:
				{
					SessionMsg msg;
					if (DecodeSession(pkt, PacketType::Bye, &msg) && msg.session == s.session_id)
						MarkDisconnected("The other player left.");
				}
				break;

				default:
					break;
			}
		}
	}

	static FrameInput ToFrameInput(const ACJV::SyncFrame& sf)
	{
		FrameInput fi;
		fi.buttons[0] = sf.buttons[0];
		fi.buttons[1] = sf.buttons[1];
		fi.coins[0] = sf.coins[0];
		fi.coins[1] = sf.coins[1];
		fi.test = sf.test;
		return fi;
	}

	static ACJV::SyncFrame ToSyncFrame(const FrameInput& fi)
	{
		ACJV::SyncFrame sf;
		sf.buttons[0] = fi.buttons[0];
		sf.buttons[1] = fi.buttons[1];
		sf.coins[0] = fi.coins[0];
		sf.coins[1] = fi.coins[1];
		sf.test = fi.test;
		return sf;
	}

	static FrameInput NetplayFrame(const ACJV::SyncFrame& live)
	{
		const u32 f = s.frame;
		const PeerInput local = MakeLocalInput(live.buttons, live.coins, live.test);
		s.local_q.Set(f + s.delay, local);

		if (!s.disconnected)
		{
			ReceiveAll();
			SendInputs();

			const Common::Timer::Value start = Common::Timer::GetCurrentValue();
			Common::Timer::Value last_pump = start;
			bool waiting_shown = false;
			while (!s.disconnected && !s.remote_q.Has(f))
			{
				if (VMManager::GetState() == VMState::Stopping)
					break;

				// Time out on silence from the peer. Allow a long first wait while the other PC is still starting up
				// (shader compile etc).
				const double waited = MillisecondsSince(start);
				const double silent = std::min(waited, MillisecondsSince(s.last_recv));
				const double timeout = s.got_remote_input ? static_cast<double>(s.opts.timeout_ms) : 90000.0;
				if (silent >= timeout)
				{
					MarkDisconnected("Lost connection to the other player.");
					break;
				}
				if (!waiting_shown && waited >= 1000.0)
				{
					waiting_shown = true;
					Console.Warning("InputSync: waiting for the other player...");
				}

				if (MillisecondsSince(s.last_send) >= 16.0)
					SendInputs();
				if (MillisecondsSince(last_pump) >= 16.0)
				{
					last_pump = Common::Timer::GetCurrentValue();
					Host::PumpMessagesOnCPUThread();
				}

				WaitReadable(1);
				ReceiveAll();
			}
		}

		static constexpr PeerInput no_input = {};
		const PeerInput* local_in = s.local_q.Get(f);
		const PeerInput* remote_in = s.remote_q.Get(f);
		const FrameInput ret = CombineInputs(s.local_side, local_in ? *local_in : no_input, remote_in ? *remote_in : no_input);

		s.remote_q.DiscardBefore(f + 1);
		s.local_q.DiscardBefore(std::min(s.remote_ack, f + 1));
		return ret;
	}

	void OnVsync()
	{
		const Mode mode = GetMode();
		if (mode == Mode::Off)
			return;

		if (!s.startup_messages_shown)
		{
			s.startup_messages_shown = true;
			if (!s.startup_warning.empty())
				ShowMessage(OSD_KEY, s.startup_warning, 20.0f);
			if (s_settings_mismatch)
				ShowMessage("InputSyncSettings", "Emulation settings differ from the other PC (or the recording). The game may desync.", 20.0f);
		}

		ACJV::SyncFrame live;
		ACJV::CaptureLiveInput(&live);

		FrameInput in;
		switch (mode)
		{
			case Mode::Record:
			{
				in = ToFrameInput(live);
				if (s.record_fp)
				{
					u8 rec[RECORDING_FRAME_SIZE];
					EncodeRecordingFrame(in, rec);
					std::fwrite(rec, sizeof(rec), 1, s.record_fp);
				}
			}
			break;

			case Mode::Replay:
			{
				if (s.frame < s.replay_frames)
					in = DecodeRecordingFrame(&s.replay[RECORDING_HEADER_SIZE + static_cast<size_t>(s.frame) * RECORDING_FRAME_SIZE]);
				else if (s.frame == s.replay_frames)
					Console.WriteLnFmt(Color_StrongGreen, "InputSync: replay finished at frame {}", s.frame);
			}
			break;

			case Mode::Host:
			case Mode::Join:
				in = NetplayFrame(live);
				break;

			default:
				break;
		}

		// Hash the state the game reached before this frame's input, so both sides compare the same thing.
		if (s.frame > 0 && (s.frame % s.hash_interval) == 0)
		{
			const u64 hash = ComputeStateHash();
			s.last_hash_frame = s.frame;
			s.last_hash = hash;
			if (s.hash_log)
			{
				std::fprintf(s.hash_log, "%u %016llx\n", s.frame, static_cast<unsigned long long>(hash));
				std::fflush(s.hash_log);
			}
			if (IsNetplay())
				OnDesyncResult(s.desync.AddLocal(s.frame, hash), s.frame);
		}

		ACJV::LatchInput(ToSyncFrame(in));
		s.frame++;

		if (s.opts.stop_after_frames != 0 && s.frame >= s.opts.stop_after_frames && !s.shutdown_requested)
		{
			s.shutdown_requested = true;
			Console.WriteLnFmt(Color_StrongGreen, "InputSync: reached frame {}, stopping.", s.frame);
			if (s.record_fp)
				std::fflush(s.record_fp);
			Host::RequestVMShutdown(false, false, false);
		}
	}

	//////////////////////////////////////////////////////////////////////////
	// Session start
	//////////////////////////////////////////////////////////////////////////

	static std::vector<u8> BuildBlob()
	{
		const std::span<u8> nvram = cdvdGetNVRAM();
		std::vector<u8> blob;
		blob.reserve(nvram.size() + ACSRAM_MAX_SIZE + s_local_settings_text.size());
		blob.insert(blob.end(), nvram.begin(), nvram.end());
		blob.insert(blob.end(), ACSRAM::buffer, ACSRAM::buffer + ACSRAM_MAX_SIZE);
		blob.insert(blob.end(), s_local_settings_text.begin(), s_local_settings_text.end());
		return blob;
	}

	static bool ApplyBlob(const std::vector<u8>& blob)
	{
		const std::span<u8> nvram = cdvdGetNVRAM();
		if (blob.size() < nvram.size() + ACSRAM_MAX_SIZE)
			return false;
		std::memcpy(nvram.data(), blob.data(), nvram.size());
		std::memcpy(ACSRAM::buffer, blob.data() + nvram.size(), ACSRAM_MAX_SIZE);
		s_remote_settings_text.assign(reinterpret_cast<const char*>(blob.data()) + nvram.size() + ACSRAM_MAX_SIZE,
			blob.size() - nvram.size() - ACSRAM_MAX_SIZE);
		return true;
	}

	static void StartLockstep()
	{
		s.local_q.Reset(0);
		s.remote_q.Reset(0);
		for (u32 f = 0; f < s.delay; f++)
		{
			s.local_q.Set(f, PeerInput{});
			s.remote_q.Set(f, PeerInput{});
		}
		s.remote_ack = s.delay;
		s.disconnected = false;
		s.desync.Reset();
		s.last_send = Common::Timer::GetCurrentValue();
	}

	static void SendBlobChunks()
	{
		for (u32 off = 0; off < s.blob.size(); off += CHUNK_SIZE)
		{
			ChunkMsg chunk;
			chunk.session = s.session_id;
			chunk.offset = off;
			chunk.total = static_cast<u32>(s.blob.size());
			const size_t len = std::min<size_t>(CHUNK_SIZE, s.blob.size() - off);
			chunk.data.assign(s.blob.begin() + off, s.blob.begin() + off + len);
			SendToPeer(Encode(chunk));
		}
	}

	static bool ConnectHost(const SessionInfo& info, Error* error)
	{
		if (!OpenSocket(s.opts.port, error))
			return false;

		const HelloMsg mine = MakeHello(info);
		std::random_device rd;
		s.session_id = (static_cast<u32>(rd()) & 0x7FFFFFFFu) | 1u;
		s.local_side = s.opts.side ? 1 : 0;
		s.delay = s.opts.delay;
		s.hash_interval = s.opts.hash_interval;
		s.blob = BuildBlob();
		s.blob_hash = HashBytes(s.blob.data(), s.blob.size());

		WelcomeMsg welcome;
		welcome.session = s.session_id;
		welcome.client_side = static_cast<u8>(s.local_side ^ 1);
		welcome.delay = static_cast<u8>(s.delay);
		welcome.hash_interval = static_cast<u16>(std::min<u32>(s.hash_interval, 0xFFFF));
		welcome.blob_size = static_cast<u32>(s.blob.size());
		welcome.blob_hash = s.blob_hash;
		welcome.settings_hash = HashString(s_local_settings_text);

		Console.WriteLnFmt(Color_StrongGreen, "InputSync: hosting on UDP port {}, waiting for the other player...", s.opts.port);

		const Common::Timer::Value start = Common::Timer::GetCurrentValue();
		Common::Timer::Value last_resend = 0;
		static constexpr double HOST_WAIT_MS = 10.0 * 60.0 * 1000.0;
		u8 buf[2048];
		while (!s.host_peer_ready)
		{
			if (s_cancel.load(std::memory_order_acquire))
			{
				Error::SetString(error, "Netplay was cancelled.");
				return false;
			}
			if (MillisecondsSince(start) >= HOST_WAIT_MS)
			{
				Error::SetString(error, "Nobody joined within 10 minutes.");
				return false;
			}

			if (s.peer_known && MillisecondsSince(last_resend) >= 250.0)
			{
				last_resend = Common::Timer::GetCurrentValue();
				SendToPeer(Encode(welcome));
				SendBlobChunks();
			}

			WaitReadable(50);
			sockaddr_in from;
			size_t len;
			while ((len = Receive(buf, sizeof(buf), &from)) > 0)
			{
				const std::span<const u8> pkt(buf, len);
				const std::optional<PacketType> type = PeekType(pkt);
				if (type == PacketType::Hello)
				{
					HelloMsg theirs;
					if (!Decode(pkt, &theirs))
					{
						// Different packet layout: most likely another protocol version.
						SendTo(from, Encode(RejectMsg{RejectReason::Protocol, {}}));
						continue;
					}
					if (s.peer_known && !SameAddress(from, s.peer))
					{
						SendTo(from, Encode(RejectMsg{RejectReason::Busy, {}}));
						continue;
					}

					std::optional<RejectReason> reject;
					if (theirs.protocol != PROTOCOL_VERSION)
						reject = RejectReason::Protocol;
					else if (theirs.build != mine.build)
						reject = RejectReason::Build;
					else if (theirs.game != mine.game)
						reject = RejectReason::Game;
					else if (theirs.media_hash != mine.media_hash)
						reject = RejectReason::Media;
					else if (theirs.bios_hash != mine.bios_hash)
						reject = RejectReason::Bios;
					if (reject.has_value())
					{
						Console.WarningFmt("InputSync: refused {}: {}", AddressToString(from), GetRejectReasonText(reject.value()));
						SendTo(from, Encode(RejectMsg{reject.value(), mine.build}));
						continue;
					}

					if (!s.peer_known)
					{
						s.peer = from;
						s.peer_known = true;
						welcome.warnings = 0;
						if (theirs.dongle_hash != mine.dongle_hash)
							welcome.warnings |= WARN_DONGLE;
						if (theirs.dip_bits != mine.dip_bits)
							welcome.warnings |= WARN_DIP;
						s.warnings = welcome.warnings;
						Console.WriteLnFmt(Color_StrongGreen, "InputSync: {} joined, sending setup data.", AddressToString(from));
						last_resend = 0;
					}
				}
				else if (s.peer_known && SameAddress(from, s.peer))
				{
					if (type == PacketType::Ready)
					{
						ReadyMsg ready;
						if (Decode(pkt, &ready) && ready.session == s.session_id && ready.blob_hash == s.blob_hash)
							s.host_peer_ready = true;
					}
					else if (type == PacketType::Input)
					{
						InputMsg msg;
						if (Decode(pkt, &msg) && msg.session == s.session_id)
							s.host_peer_ready = true;
					}
				}
			}
		}

		return true;
	}

	static bool ConnectJoin(const SessionInfo& info, Error* error)
	{
		std::string host;
		u16 port = s.opts.port;
		if (!ParseHostPort(s.opts.address, &host, &port))
		{
			Error::SetStringFmt(error, "'{}' is not a valid address. Use something like 203.0.113.5:7656.", s.opts.address);
			return false;
		}
		if (!ResolveAddress(host, port, &s.peer))
		{
			Error::SetStringFmt(error, "Could not find the host '{}'.", host);
			return false;
		}
		s.peer_known = true;
		if (!OpenSocket(0, error))
			return false;

		const std::vector<u8> hello = Encode(MakeHello(info));
		Console.WriteLnFmt(Color_StrongGreen, "InputSync: connecting to {}...", AddressToString(s.peer));

		const Common::Timer::Value start = Common::Timer::GetCurrentValue();
		Common::Timer::Value last_hello = 0;
		static constexpr double JOIN_WAIT_MS = 30.0 * 1000.0;
		std::optional<WelcomeMsg> welcome;
		std::vector<u8> blob;
		std::vector<bool> have_chunk;
		u32 chunks_left = 0;
		u8 buf[2048];

		for (;;)
		{
			if (s_cancel.load(std::memory_order_acquire))
			{
				Error::SetString(error, "Netplay was cancelled.");
				return false;
			}
			if (MillisecondsSince(start) >= JOIN_WAIT_MS)
			{
				Error::SetString(error, welcome.has_value() ?
					"The connection broke while receiving setup data from the host." :
					"The host did not answer. Check the address and port, that the host is waiting, and that the "
					"host's router forwards the UDP port.");
				return false;
			}
			if (!welcome.has_value() && MillisecondsSince(last_hello) >= 250.0)
			{
				last_hello = Common::Timer::GetCurrentValue();
				SendToPeer(hello);
			}

			WaitReadable(50);
			sockaddr_in from;
			size_t len;
			while ((len = Receive(buf, sizeof(buf), &from)) > 0)
			{
				if (!SameAddress(from, s.peer))
					continue;
				const std::span<const u8> pkt(buf, len);
				const std::optional<PacketType> type = PeekType(pkt);
				if (type == PacketType::Reject)
				{
					RejectMsg rej;
					if (Decode(pkt, &rej))
					{
						std::string text = GetRejectReasonText(rej.reason);
						if (rej.reason == RejectReason::Build && !rej.detail.empty())
							text += fmt::format(" (host: {}, you: {})", rej.detail, GetBuildId());
						Error::SetString(error, std::move(text));
					}
					else
					{
						Error::SetString(error, "The host refused the connection.");
					}
					return false;
				}
				else if (type == PacketType::Welcome)
				{
					WelcomeMsg msg;
					if (!welcome.has_value() && Decode(pkt, &msg) && msg.blob_size <= 1024 * 1024)
					{
						welcome = msg;
						s.session_id = msg.session;
						blob.assign(msg.blob_size, 0);
						chunks_left = (msg.blob_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
						have_chunk.assign(chunks_left, false);
					}
				}
				else if (type == PacketType::Chunk && welcome.has_value())
				{
					ChunkMsg chunk;
					if (Decode(pkt, &chunk) && chunk.session == s.session_id && chunk.total == blob.size() &&
						(chunk.offset % CHUNK_SIZE) == 0)
					{
						const u32 idx = chunk.offset / CHUNK_SIZE;
						if (idx < have_chunk.size() && !have_chunk[idx])
						{
							std::memcpy(blob.data() + chunk.offset, chunk.data.data(), chunk.data.size());
							have_chunk[idx] = true;
							chunks_left--;
						}
					}
				}
			}

			if (welcome.has_value() && chunks_left == 0)
				break;
		}

		s.blob_hash = HashBytes(blob.data(), blob.size());
		if (s.blob_hash != welcome->blob_hash || !ApplyBlob(blob))
		{
			Error::SetString(error, "The setup data from the host arrived damaged. Try again.");
			return false;
		}

		s.local_side = welcome->client_side;
		s.delay = welcome->delay;
		s.hash_interval = welcome->hash_interval ? welcome->hash_interval : DEFAULT_HASH_INTERVAL;
		s.warnings = welcome->warnings;
		s_expected_settings_hash = welcome->settings_hash;

		const std::vector<u8> ready = Encode(ReadyMsg{s.session_id, s.blob_hash});
		for (int i = 0; i < 3; i++)
			SendToPeer(ready);
		return true;
	}

	static bool ConnectRecording(const SessionInfo& info, Error* error)
	{
		s.hash_interval = s.opts.hash_interval;
		const std::span<u8> nvram = cdvdGetNVRAM();

		RecordingHeader hdr;
		hdr.game = info.game_id;
		hdr.settings_hash = HashString(s_local_settings_text);
		hdr.sram_hash = HashBytes(ACSRAM::buffer, ACSRAM_MAX_SIZE);
		hdr.nvram_hash = HashBytes(nvram.data(), nvram.size());

		if (s.opts.mode == Mode::Record)
		{
			s.record_fp = FileSystem::OpenCFile(s.opts.path.c_str(), "wb");
			if (!s.record_fp)
			{
				Error::SetStringFmt(error, "Could not create the input recording '{}'.", s.opts.path);
				return false;
			}
			const std::vector<u8> header = EncodeRecordingHeader(hdr);
			std::fwrite(header.data(), header.size(), 1, s.record_fp);
			Console.WriteLnFmt(Color_StrongGreen, "InputSync: recording inputs to '{}'", s.opts.path);
			return true;
		}

		std::optional<std::vector<u8>> data = FileSystem::ReadBinaryFile(s.opts.path.c_str());
		RecordingHeader file_hdr;
		if (!data.has_value() || !DecodeRecordingHeader(data.value(), &file_hdr))
		{
			Error::SetStringFmt(error, "Could not read the input recording '{}'.", s.opts.path);
			return false;
		}
		if (file_hdr.game != hdr.game)
		{
			Error::SetStringFmt(error, "The input recording is for {}, not {}.", file_hdr.game, hdr.game);
			return false;
		}
		if (file_hdr.sram_hash != hdr.sram_hash || file_hdr.nvram_hash != hdr.nvram_hash)
			s.startup_warning = "The game's saved settings (SRAM/NVRAM) differ from when this recording was made. The replay may not match.";
		s_expected_settings_hash = file_hdr.settings_hash;
		s.replay = std::move(data.value());
		s.replay_frames = (s.replay.size() - RECORDING_HEADER_SIZE) / RECORDING_FRAME_SIZE;
		Console.WriteLnFmt(Color_StrongGreen, "InputSync: replaying {} frames from '{}'", s.replay_frames, s.opts.path);
		return true;
	}

	bool Connect(const SessionInfo& info, Error* error)
	{
		const Mode mode = GetMode();
		if (mode == Mode::Off)
			return true;

		// Settings text comes from LoadCoreSettings() (before GameDB fixes), which already ran with our overrides.
		if (s_local_settings_text.empty())
			s_local_settings_text = BuildSettingsText();

		if (!s.opts.hash_log.empty())
		{
			s.hash_log = FileSystem::OpenCFile(s.opts.hash_log.c_str(), "w");
			if (!s.hash_log)
				Console.ErrorFmt("InputSync: could not create hash log '{}'", s.opts.hash_log);
		}

		bool ok;
		switch (mode)
		{
			case Mode::Record:
			case Mode::Replay:
				ok = ConnectRecording(info, error);
				break;
			case Mode::Host:
				ok = ConnectHost(info, error);
				break;
			case Mode::Join:
				ok = ConnectJoin(info, error);
				break;
			default:
				ok = false;
				break;
		}
		if (!ok)
			return false;

		if (s.hash_interval == 0)
			s.hash_interval = DEFAULT_HASH_INTERVAL;

		if (mode == Mode::Replay && s_expected_settings_hash != HashString(s_local_settings_text))
			s_settings_mismatch = true;

		if (IsNetplay())
		{
			StartLockstep();
			std::string warn;
			if (s.warnings & WARN_DONGLE)
				warn += "The two PCs have different dongle files. ";
			if (s.warnings & WARN_DIP)
				warn += "The two PCs have different DIP switch settings. ";
			if (!warn.empty())
				s.startup_warning = warn + "The game may desync.";
			Console.WriteLnFmt(Color_StrongGreen, "InputSync: connected to {}. You are P{}, input delay {} frames.",
				AddressToString(s.peer), s.local_side + 1, s.delay);
			Host::AddIconOSDMessage(OSD_KEY, ICON_FA_USERS,
				fmt::format("Netplay connected. You are Player {} (delay {} frames).", s.local_side + 1, s.delay),
				Host::OSD_INFO_DURATION);
		}

		s.frame = 0;
		ACJV::SetInputSyncEnabled(true);
		return true;
	}

	void EndSession()
	{
		if (s.sock != INVALID_SOCK && s.peer_known && s.session_id != 0)
		{
			const std::vector<u8> bye = EncodeSession(PacketType::Bye, SessionMsg{s.session_id});
			for (int i = 0; i < 3; i++)
				SendToPeer(bye);
		}
		CloseSocket();

		if (s.record_fp)
		{
			std::fclose(s.record_fp);
			Console.WriteLnFmt(Color_StrongGreen, "InputSync: recorded {} frames to '{}'", s.frame, s.opts.path);
		}
		if (s.hash_log)
			std::fclose(s.hash_log);

		if (IsNetplay() && s.desync.GetMatchedCount() > 0 && !s.desync.HasDesynced())
			Console.WriteLnFmt(Color_StrongGreen, "InputSync: {} state checks matched, no desync.", s.desync.GetMatchedCount());

		const bool was_active = IsActive();
		s = Session();
		s_remote_settings_text.clear();
		s_local_settings_text.clear();
		s_expected_settings_hash = 0;
		s_settings_mismatch = false;
		s_mode.store(Mode::Off, std::memory_order_release);
		if (was_active)
			ACJV::SetInputSyncEnabled(false);
	}

	std::string GetStatusText()
	{
		switch (GetMode())
		{
			case Mode::Record:
				return "Recording inputs";
			case Mode::Replay:
				return "Replaying inputs";
			case Mode::Host:
			case Mode::Join:
				return s.disconnected ? "Netplay: disconnected" :
										fmt::format("Netplay: Player {}, delay {}", s.local_side + 1, s.delay);
			default:
				return {};
		}
	}
} // namespace InputSync
