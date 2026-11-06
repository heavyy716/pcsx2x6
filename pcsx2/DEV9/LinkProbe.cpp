// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#include "LinkProbe.h"

#include "common/Console.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

namespace LinkProbe
{
	bool enabled = false;

	namespace
	{
		std::mutex s_mutex;
		std::FILE* s_log = nullptr;
		std::FILE* s_pcap = nullptr;
		std::chrono::steady_clock::time_point s_start;
		std::unordered_map<u64, u64> s_hits;
		u64 s_frames[2] = {};

		std::string GetEnv(const char* name)
		{
#ifdef _WIN32
			char* buf = nullptr;
			size_t len = 0;
			std::string ret;
			if (_dupenv_s(&buf, &len, name) == 0 && buf)
			{
				ret = buf;
				std::free(buf);
			}
			return ret;
#else
			const char* v = std::getenv(name);
			return v ? std::string(v) : std::string();
#endif
		}

		std::FILE* OpenFile(const std::string& path, const char* mode)
		{
#ifdef _WIN32
			std::FILE* fp = nullptr;
			if (fopen_s(&fp, path.c_str(), mode) != 0)
				return nullptr;
			return fp;
#else
			return std::fopen(path.c_str(), mode);
#endif
		}

		double Now()
		{
			return std::chrono::duration<double>(std::chrono::steady_clock::now() - s_start).count();
		}

		const char* Region(u32 addr)
		{
			const u32 t = addr >> 16;
			const u32 o = addr & 0xFFFF;
			if (t == 0x1000)
			{
				if (o >= 0x40 && o < 0x60)
					return "ATA";
				if (o < 0x100)
					return "SPEED";
				if (o < 0x4800)
					return "SMAP";
				return "DEV9";
			}
			if (t == 0x1F80)
			{
				if (o >= 0x1040 && o < 0x1050)
					return "SIO0";
				if (o >= 0x1050 && o < 0x1060)
					return "SIO1";
				if (o >= 0x1600 && o < 0x1700)
					return "USB";
				if (o >= 0x8400 && o < 0x8580)
					return "ILINK";
				return "IOPHW";
			}
			if (t == 0x1240)
				return "ACJV";
			if (t == 0x1241)
				return "ACCORE";
			if ((t & 0xFF00) == 0x1300)
				return "ACINTR";
			if ((t & 0xFF00) == 0x1600)
				return "ACATA";
			return "AC?";
		}

		void WriteLineLocked(const char* line)
		{
			if (!s_log)
				return;
			std::fprintf(s_log, "[%10.4f] %s\n", Now(), line);
		}

		void PcapWriteLocked(const void* data, int len)
		{
			if (!s_pcap)
				return;
			const auto now = std::chrono::system_clock::now().time_since_epoch();
			const u64 us = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(now).count());
			const u32 rec[4] = {static_cast<u32>(us / 1000000), static_cast<u32>(us % 1000000),
				static_cast<u32>(len), static_cast<u32>(len)};
			std::fwrite(rec, sizeof(rec), 1, s_pcap);
			std::fwrite(data, 1, static_cast<size_t>(len), s_pcap);
		}

		int DecodeFrame(char* out, size_t cap, const u8* p, int len)
		{
			if (len < 14)
				return std::snprintf(out, cap, "runt len=%d", len);
			int n = std::snprintf(out, cap,
				"len=%d dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x",
				len, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]);
			const u16 type = static_cast<u16>((p[12] << 8) | p[13]);
			const u8* pl = p + 14;
			const int plen = len - 14;
			auto add = [&](const char* fmt, auto... args) {
				if (n >= 0 && static_cast<size_t>(n) < cap)
					n += std::snprintf(out + n, cap - n, fmt, args...);
			};
			if (type == 0x0800 && plen >= 20)
			{
				const int ihl = (pl[0] & 0x0F) * 4;
				const u8 proto = pl[9];
				add(" IPv4 %u.%u.%u.%u->%u.%u.%u.%u proto=%u", pl[12], pl[13], pl[14], pl[15],
					pl[16], pl[17], pl[18], pl[19], proto);
				if ((proto == 17 || proto == 6) && plen >= ihl + 4)
					add(" %s %u->%u", proto == 17 ? "UDP" : "TCP",
						(pl[ihl] << 8) | pl[ihl + 1], (pl[ihl + 2] << 8) | pl[ihl + 3]);
			}
			else if (type == 0x0806 && plen >= 28)
			{
				add(" ARP op=%u %u.%u.%u.%u->%u.%u.%u.%u", (pl[6] << 8) | pl[7],
					pl[14], pl[15], pl[16], pl[17], pl[24], pl[25], pl[26], pl[27]);
			}
			else
			{
				add(" type=%04x", type);
			}
			add("%s", " |");
			for (int i = 0; i < plen && i < 32; i++)
				add(" %02x", pl[i]);
			return n;
		}
	} // namespace

	void Init()
	{
		std::lock_guard lock(s_mutex);
		if (s_log)
			return;
		const std::string path = GetEnv("PCSX2X6_LINKLOG");
		if (path.empty())
			return;
		s_log = OpenFile(path, "a");
		if (!s_log)
		{
			Console.Error("LinkProbe: cannot open PCSX2X6_LINKLOG=%s", path.c_str());
			return;
		}
		s_start = std::chrono::steady_clock::now();
		s_hits.clear();
		s_frames[0] = s_frames[1] = 0;
		const std::time_t wall = std::time(nullptr);
		char stamp[64] = {};
		std::tm tm_local = {};
#ifdef _WIN32
		localtime_s(&tm_local, &wall);
#else
		localtime_r(&wall, &tm_local);
#endif
		std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm_local);
		std::fprintf(s_log, "==== LinkProbe session start %s (vlan=%s mac=%s) ====\n", stamp,
			GetEnv("PCSX2X6_VLAN").c_str(), GetEnv("PCSX2X6_VLAN_MAC").c_str());
		std::fflush(s_log);

		const std::string pcap = GetEnv("PCSX2X6_LINKPCAP");
		if (!pcap.empty())
		{
			// Each session gets a fresh capture; the pcap format has no append marker.
			s_pcap = OpenFile(pcap, "wb");
			if (s_pcap)
			{
				const u32 hdr[6] = {0xa1b2c3d4u, 0x00040002u, 0, 0, 65535, 1};
				std::fwrite(hdr, sizeof(hdr), 1, s_pcap);
			}
			else
				Console.Error("LinkProbe: cannot open PCSX2X6_LINKPCAP=%s", pcap.c_str());
		}
		enabled = true;
		Console.WriteLn(Color_StrongGreen, "LinkProbe: logging arcade link activity to %s", path.c_str());
	}

	void Shutdown()
	{
		std::lock_guard lock(s_mutex);
		if (!s_log)
			return;
		enabled = false;
		std::map<u64, u64> sorted;
		for (const auto& [k, v] : s_hits)
			sorted.emplace(((k >> 32) << 16) | (k & 0xFFFF), v);
		std::fprintf(s_log, "---- summary: %llu TX frames, %llu RX frames, %zu MMIO keys ----\n",
			static_cast<unsigned long long>(s_frames[0]), static_cast<unsigned long long>(s_frames[1]), sorted.size());
		for (const auto& [k, v] : sorted)
		{
			const u32 addr = static_cast<u32>(k >> 16);
			const char dir = static_cast<char>((k >> 8) & 0xFF);
			const int width = static_cast<int>(k & 0xFF);
			std::fprintf(s_log, "SUM %-6s %c%-2d %08X hits=%llu\n", Region(addr), dir, width, addr,
				static_cast<unsigned long long>(v));
		}
		std::fprintf(s_log, "==== LinkProbe session end ====\n");
		std::fclose(s_log);
		s_log = nullptr;
		if (s_pcap)
		{
			std::fclose(s_pcap);
			s_pcap = nullptr;
		}
	}

	void IopAccess(char dir, u32 addr, int width, u32 value)
	{
		std::lock_guard lock(s_mutex);
		if (!s_log)
			return;
		const u64 key = (static_cast<u64>(addr) << 32) | (static_cast<u64>(static_cast<u8>(dir)) << 8) | static_cast<u64>(width);
		const u64 hit = ++s_hits[key];
		if (hit > 4 && (hit & (hit - 1)) != 0)
			return;
		char line[128];
		std::snprintf(line, sizeof(line), "MMIO %-6s %c%-2d %08X = %0*X  (hit %llu)", Region(addr), dir, width, addr,
			width / 4, value, static_cast<unsigned long long>(hit));
		WriteLineLocked(line);
		if (hit == 1)
			std::fflush(s_log);
	}

	void Frame(const char* dir, const void* data, int len)
	{
		std::lock_guard lock(s_mutex);
		if (!s_log)
			return;
		const bool tx = dir[0] == 'T';
		const u64 count = ++s_frames[tx ? 0 : 1];
		PcapWriteLocked(data, len);
		if (count > 5000 && (count % 1000) != 0)
			return;
		char line[512];
		int n = std::snprintf(line, sizeof(line), "ETH %s #%llu ", dir, static_cast<unsigned long long>(count));
		DecodeFrame(line + n, sizeof(line) - n, static_cast<const u8*>(data), len);
		WriteLineLocked(line);
		std::fflush(s_log);
		if (s_pcap)
			std::fflush(s_pcap);
	}

	void Note(const char* fmt, ...)
	{
		std::lock_guard lock(s_mutex);
		if (!s_log)
			return;
		char line[512];
		va_list ap;
		va_start(ap, fmt);
		std::vsnprintf(line, sizeof(line), fmt, ap);
		va_end(ap);
		WriteLineLocked(line);
		std::fflush(s_log);
	}
} // namespace LinkProbe
