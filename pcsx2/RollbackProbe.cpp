// SPDX-FileCopyrightText: 2026 vs-rollback contributors
// SPDX-License-Identifier: GPL-3.0+

#include "RollbackProbe.h"

#include "Config.h"
#include "Counters.h"
#include "DEV9/ACJV.h"
#include "DEV9/vlan_link.h"
#include "SaveState.h"
#include "VMManager.h"

#include "common/Console.h"
#include "common/Error.h"
#include "common/FileSystem.h"

#include "fmt/format.h"
#define XXH_INLINE_ALL 1
#include "xxhash.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace RollbackProbe
{
	bool s_active = !VlanLink::GetEnv("PCSX2X6_RBPROBE").empty();

	namespace
	{
		using Clock = std::chrono::steady_clock;

		enum class Phase
		{
			Idle,
			Burst,
			Saves,
			Record,
			Replay,
		};

		static constexpr u32 MAX_SECTIONS = 32;
		using Hashes = std::array<u64, MAX_SECTIONS>;

		bool s_init = false;
		std::FILE* s_log = nullptr;
		Clock::time_point s_start;

		u32 s_start_frame = 1800;
		u32 s_period = 600;
		u32 s_burst = 60;
		u32 s_k = 8;

		Phase s_phase = Phase::Idle;
		u64 s_frame = 0; // OnVSync calls seen
		u64 s_next_cycle = 0;
		u32 s_cycle = 0;
		u32 s_step = 0;

		Clock::time_point s_frame_end; // end of the previous OnVSync
		bool s_have_frame_end = false;
		std::vector<double> s_busy_ms; // emulation work per frame while idle (before the limiter)
		std::vector<double> s_samples;

		LimiterModeType s_saved_limiter = LimiterModeType::Nominal;
		Clock::time_point s_burst_start;

		ArchiveEntryList s_s0;   // state at the start of the recorded window
		ArchiveEntryList s_work; // scratch state for per-frame saves
		u32 s_s0_size = 0;
		bool s_sizes_logged = false;

		std::vector<ACJV::InputFrame> s_inputs;
		std::vector<Hashes> s_hashes;
		std::vector<u8> s_rec1; // full recorded buffer for frame 1 (detailed diff)
		std::vector<std::pair<uptr, u32>> s_rec1_layout;
		double s_load_ms = 0;
		double s_replay_overhead_ms = 0;
		std::vector<double> s_replay_ms;
		u32 s_mismatch_frames = 0;
		u32 s_first_mismatch = 0;
		u32 s_total_cycles_ok = 0;
		u32 s_total_cycles_bad = 0;

		double Ms(Clock::duration d)
		{
			return std::chrono::duration<double, std::milli>(d).count();
		}

		void Log(const std::string& line)
		{
			if (!s_log)
				return;
			const double t = std::chrono::duration<double>(Clock::now() - s_start).count();
			std::fprintf(s_log, "%9.3f f=%-7llu %s\n", t, static_cast<unsigned long long>(g_FrameCount), line.c_str());
			std::fflush(s_log);
		}

		u32 EnvU32(const char* name, u32 def)
		{
			const std::string v = VlanLink::GetEnv(name);
			if (v.empty())
				return def;
			return static_cast<u32>(std::strtoul(v.c_str(), nullptr, 0));
		}

		std::string Stats(std::vector<double>& v)
		{
			if (v.empty())
				return "n=0";
			std::sort(v.begin(), v.end());
			double sum = 0;
			for (double x : v)
				sum += x;
			const double p95 = v[std::min<size_t>(v.size() - 1, (v.size() * 95) / 100)];
			return fmt::format("n={} min={:.2f} avg={:.2f} p95={:.2f} max={:.2f} ms", v.size(), v.front(), sum / v.size(), p95, v.back());
		}

		void Init()
		{
			s_init = true;
			s_start = Clock::now();
			const std::string path = VlanLink::GetEnv("PCSX2X6_RBPROBE");
			s_log = FileSystem::OpenCFile(path.c_str(), "wb");
			if (!s_log)
			{
				Console.Error(fmt::format("RollbackProbe: cannot open {}", path));
				s_active = false;
				return;
			}
			s_start_frame = EnvU32("PCSX2X6_RBPROBE_START", 1800);
			s_period = std::max<u32>(EnvU32("PCSX2X6_RBPROBE_PERIOD", 600), 200);
			s_burst = std::clamp<u32>(EnvU32("PCSX2X6_RBPROBE_BURST", 60), 10, 600);
			s_k = std::clamp<u32>(EnvU32("PCSX2X6_RBPROBE_FRAMES", 8), 1, 30);
			s_next_cycle = s_start_frame;
			Console.WriteLn(fmt::format("RollbackProbe: active, log {}", path));
			Log(fmt::format("RBPROBE start={} period={} burst={} rollback_frames={}", s_start_frame, s_period, s_burst, s_k));
			Log(fmt::format("CONFIG mtvu={} ee_cycle_rate={} ee_cycle_skip={} renderer={} upscale={} vsync={} vfreq={:.3f} target_speed={:.2f}",
				EmuConfig.Speedhacks.vuThread ? 1 : 0, static_cast<int>(EmuConfig.Speedhacks.EECycleRate),
				static_cast<int>(EmuConfig.Speedhacks.EECycleSkip), static_cast<int>(EmuConfig.GS.Renderer),
				EmuConfig.GS.UpscaleMultiplier, EmuConfig.GS.VsyncEnable ? 1 : 0, VMManager::GetFrameRate(), VMManager::GetTargetSpeed()));
			if (EmuConfig.Speedhacks.vuThread)
				Log("WARN MTVU is on: replays are not expected to be deterministic");
		}

		void HashSections(const ArchiveEntryList& list, Hashes* out)
		{
			out->fill(0);
			const u32 n = std::min<u32>(static_cast<u32>(list.GetLength()), MAX_SECTIONS);
			for (u32 i = 0; i < n; i++)
			{
				const ArchiveEntry& e = list[i];
				(*out)[i] = e.GetDataSize() ? XXH3_64bits(list.GetPtr(static_cast<uint>(e.GetDataIndex())), e.GetDataSize()) : 0;
			}
		}

		// Nearest FreezeTag before an offset in the internals section: a 32-byte, zero-padded ASCII tag.
		std::string NearestTag(const u8* base, uptr start, uptr off)
		{
			const uptr lo = (off > start + (1u << 20)) ? off - (1u << 20) : start;
			for (uptr p = off; p + 1 > lo; p--)
			{
				const u8* s = base + p;
				u32 n = 0;
				while (n < 32 && s[n] >= 0x20 && s[n] < 0x7f)
					n++;
				if (n >= 3 && n < 32 && (p == 0 || base[p - 1] == 0 || p == start))
				{
					bool pad = true;
					for (u32 i = n; i < 32 && pad; i++)
						pad = (s[i] == 0);
					if (pad)
						return fmt::format("'{}'+{:#x}", std::string(reinterpret_cast<const char*>(s), n), off - p);
				}
				if (p == 0)
					break;
			}
			return "?";
		}

		// Byte diff of two serialized states section by section.
		void DiffStates(const char* what, const u8* a, const std::vector<std::pair<uptr, u32>>& la, const ArchiveEntryList& b)
		{
			const u32 n = std::min<u32>(static_cast<u32>(la.size()), static_cast<u32>(b.GetLength()));
			bool any = false;
			for (u32 i = 0; i < n; i++)
			{
				const ArchiveEntry& eb = b[i];
				const u8* pa = a + la[i].first;
				const u8* pb = b.GetPtr(static_cast<uint>(eb.GetDataIndex()));
				const u32 sa = la[i].second;
				const u32 sb = eb.GetDataSize();
				const u32 m = std::min(sa, sb);
				u32 diffs = 0;
				std::string firsts;
				for (u32 j = 0; j < m; j++)
				{
					if (pa[j] != pb[j])
					{
						if (diffs < 6)
						{
							firsts += fmt::format(" +{:#x}({:02x}->{:02x}", j, pa[j], pb[j]);
							if (i == 0)
								firsts += " " + NearestTag(a, la[i].first, la[i].first + j);
							firsts += ")";
						}
						diffs++;
					}
				}
				if (diffs || sa != sb)
				{
					any = true;
					Log(fmt::format("{} DIFF {} size {}/{} bytes_differ={}{}", what, eb.GetFilename(), sa, sb, diffs, firsts));
				}
			}
			if (!any)
				Log(fmt::format("{} identical", what));
		}

		std::vector<std::pair<uptr, u32>> Layout(const ArchiveEntryList& l)
		{
			std::vector<std::pair<uptr, u32>> r;
			for (size_t i = 0; i < l.GetLength(); i++)
				r.emplace_back(l[static_cast<uint>(i)].GetDataIndex(), l[static_cast<uint>(i)].GetDataSize());
			return r;
		}

		bool Save(ArchiveEntryList& list, u32* size, double* ms)
		{
			Error error;
			const Clock::time_point t0 = Clock::now();
			const bool ok = SaveState_SaveToMemory(list, size, &error);
			if (ms)
				*ms = Ms(Clock::now() - t0);
			if (!ok)
				Log(fmt::format("ERROR save failed: {}", error.GetDescription()));
			return ok;
		}

		void AbortCycle(const char* why)
		{
			if (s_phase == Phase::Burst)
				VMManager::SetLimiterMode(s_saved_limiter);
			if (s_phase == Phase::Replay)
				ACJV::SetInputOverride(nullptr);
			Log(fmt::format("CYCLE {} aborted: {}", s_cycle, why));
			s_phase = Phase::Idle;
			s_next_cycle = s_frame + s_period;
		}

		void StartCycle()
		{
			s_cycle++;
			Log(fmt::format("CYCLE {} idle_busy {} (16.68 ms = 100% speed budget)", s_cycle, Stats(s_busy_ms)));
			s_busy_ms.clear();
			s_saved_limiter = VMManager::GetLimiterMode();
			VMManager::SetLimiterMode(LimiterModeType::Unlimited);
			s_burst_start = Clock::now();
			s_step = 0;
			s_phase = Phase::Burst;
		}

		void StepBurst()
		{
			if (++s_step < s_burst)
				return;
			const double secs = std::chrono::duration<double>(Clock::now() - s_burst_start).count();
			VMManager::SetLimiterMode(s_saved_limiter);
			const double fps = s_burst / secs;
			Log(fmt::format("BURST unthrottled {} frames in {:.3f} s = {:.1f} fps ({:.0f}% of {:.2f} Hz)", s_burst, secs, fps,
				100.0 * fps / VMManager::GetFrameRate(), VMManager::GetFrameRate()));
			s_samples.clear();
			s_step = 0;
			s_phase = Phase::Saves;
		}

		void StepSaves()
		{
			u32 size = 0;
			double ms = 0;
			if (!Save(s_work, &size, &ms))
			{
				AbortCycle("save failed");
				return;
			}
			s_samples.push_back(ms);
			if (!s_sizes_logged)
			{
				s_sizes_logged = true;
				std::string parts;
				for (size_t i = 0; i < s_work.GetLength(); i++)
				{
					const ArchiveEntry& e = s_work[static_cast<uint>(i)];
					parts += fmt::format(" {}={}", e.GetFilename(), e.GetDataSize());
				}
				Log(fmt::format("STATE size={} bytes ({:.2f} MiB) sections:{}", size, size / 1048576.0, parts));
			}
			if (++s_step < s_burst)
				return;
			Log(fmt::format("SAVE per-frame in-memory {}", Stats(s_samples)));

			// Start the determinism window: S0 + inputs for the frame that follows.
			double ms0 = 0;
			if (!Save(s_s0, &s_s0_size, &ms0))
			{
				AbortCycle("S0 save failed");
				return;
			}
			s_inputs.assign(s_k + 1, ACJV::InputFrame{});
			s_hashes.assign(s_k + 1, Hashes{});
			ACJV::CaptureInputFrame(&s_inputs[0]);
			s_inputs[0].coins[0] = s_inputs[0].coins[1] = 0; // already in S0
			HashSections(s_s0, &s_hashes[0]);
			s_step = 0;
			s_phase = Phase::Record;
		}

		void StepRecord()
		{
			s_step++;
			ACJV::CaptureInputFrame(&s_inputs[s_step]);
			if (!Save(s_work, nullptr, nullptr))
			{
				AbortCycle("record save failed");
				return;
			}
			HashSections(s_work, &s_hashes[s_step]);
			if (s_step == 1)
			{
				s_rec1.assign(s_work.GetBuffer().begin(), s_work.GetBuffer().begin() +
					(s_work[static_cast<uint>(s_work.GetLength() - 1)].GetDataIndex() + s_work[static_cast<uint>(s_work.GetLength() - 1)].GetDataSize()));
				s_rec1_layout = Layout(s_work);
			}
			if (s_step < s_k)
				return;

			// Roll back to S0.
			Error error;
			const Clock::time_point t0 = Clock::now();
			if (!SaveState_LoadFromMemory(s_s0, &error))
			{
				Log(fmt::format("ERROR load failed: {}", error.GetDescription()));
				AbortCycle("load failed");
				return;
			}
			s_load_ms = Ms(Clock::now() - t0);

			// Round trip: saving right after the load must reproduce S0.
			double rt_ms = 0;
			if (Save(s_work, nullptr, &rt_ms))
			{
				Hashes h;
				HashSections(s_work, &h);
				if (h == s_hashes[0])
					Log(fmt::format("LOAD {:.2f} ms; round-trip save identical", s_load_ms));
				else
				{
					Log(fmt::format("LOAD {:.2f} ms; round-trip save DIFFERS", s_load_ms));
					DiffStates("ROUNDTRIP", s_s0.GetBuffer().data(), Layout(s_s0), s_work);
				}
			}

			ACJV::SetInputOverride(&s_inputs[0]);
			s_replay_ms.clear();
			s_replay_overhead_ms = 0;
			s_mismatch_frames = 0;
			s_first_mismatch = 0;
			s_step = 0;
			s_phase = Phase::Replay;
		}

		void StepReplay(double frame_ms)
		{
			s_step++;
			ACJV::SetInputOverride(&s_inputs[s_step]);
			const Clock::time_point t0 = Clock::now();
			if (!Save(s_work, nullptr, nullptr))
			{
				AbortCycle("replay save failed");
				return;
			}
			Hashes h;
			HashSections(s_work, &h);
			s_replay_overhead_ms += Ms(Clock::now() - t0);
			s_replay_ms.push_back(frame_ms);

			if (h != s_hashes[s_step])
			{
				if (!s_mismatch_frames)
				{
					s_first_mismatch = s_step;
					std::string secs;
					for (size_t i = 0; i < s_work.GetLength() && i < MAX_SECTIONS; i++)
					{
						if (h[i] != s_hashes[s_step][i])
							secs += " " + s_work[static_cast<uint>(i)].GetFilename();
					}
					Log(fmt::format("DESYNC at replay frame {}/{}: sections{}", s_step, s_k, secs));
					if (s_step == 1)
						DiffStates("DESYNC1", s_rec1.data(), s_rec1_layout, s_work);
				}
				s_mismatch_frames++;
			}

			if (s_step < s_k)
				return;

			ACJV::SetInputOverride(nullptr);
			std::string per;
			for (double ms : s_replay_ms)
				per += fmt::format(" {:.1f}", ms);
			const double first = s_replay_ms.empty() ? 0 : s_replay_ms.front();
			double total = 0;
			for (double ms : s_replay_ms)
				total += ms;
			Log(fmt::format("REPLAY {} frames: load {:.2f} ms + emulate{} ms (first/cold {:.1f}) = {:.1f} ms total; probe save+hash outside that {:.1f} ms",
				s_k, s_load_ms, per, first, s_load_ms + total, s_replay_overhead_ms));
			if (s_mismatch_frames)
			{
				s_total_cycles_bad++;
				Log(fmt::format("RESULT cycle {} DESYNC: {} of {} frames differ, first at {}", s_cycle, s_mismatch_frames, s_k, s_first_mismatch));
			}
			else
			{
				s_total_cycles_ok++;
				Log(fmt::format("RESULT cycle {} deterministic over {} frames", s_cycle, s_k));
			}
			Log(fmt::format("TOTALS deterministic={} desync={}", s_total_cycles_ok, s_total_cycles_bad));
			s_phase = Phase::Idle;
			s_next_cycle = s_frame + s_period;
		}
	} // namespace

	void BeforeThrottleImpl()
	{
		if (!s_init || s_phase != Phase::Idle || !s_have_frame_end)
			return;
		s_busy_ms.push_back(Ms(Clock::now() - s_frame_end));
	}

	bool SkipThrottleImpl()
	{
		return s_phase == Phase::Replay;
	}

	void OnVSyncImpl()
	{
		if (!s_init)
		{
			Init();
			if (!s_active)
				return;
		}

		const Clock::time_point now = Clock::now();
		const double frame_ms = s_have_frame_end ? Ms(now - s_frame_end) : 0.0;
		s_frame++;

		if (VMManager::Internal::IsExecutionInterrupted())
		{
			if (s_phase != Phase::Idle)
				AbortCycle("execution interrupted (pause/menu)");
			s_have_frame_end = false;
			return;
		}

		switch (s_phase)
		{
			case Phase::Idle:
				if (s_frame >= s_next_cycle)
					StartCycle();
				break;
			case Phase::Burst:
				StepBurst();
				break;
			case Phase::Saves:
				StepSaves();
				break;
			case Phase::Record:
				StepRecord();
				break;
			case Phase::Replay:
				StepReplay(frame_ms);
				break;
		}

		s_frame_end = Clock::now();
		s_have_frame_end = true;
	}
} // namespace RollbackProbe
