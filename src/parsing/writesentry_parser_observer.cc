// Copyright 2026 The Chromium Authors
// Selected-worker parser observation. This is diagnostic-only code.

#include "src/parsing/writesentry_parser_observer.h"

#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH) || \
    defined(V8_ENABLE_WRITESENTRY_PARSER_TIMING)

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
#include "writesentry/writesentry.h"
#endif

#if defined(WRITESENTRY_FAULT_TESTS)
#include "test_fault_hooks.h"
#endif

namespace v8::internal {
namespace {

constexpr char kPrefix[] = "WRITESENTRY_OBSERVATION ";
std::atomic<bool> g_collect{false};
std::atomic<uint32_t> g_next_job{0};
std::atomic<uint32_t> g_program_entries{0};
std::atomic<uint32_t> g_function_entries{0};
std::atomic<uint32_t> g_background_entries{0};
std::atomic<uint32_t> g_destructions{0};
std::atomic<uint32_t> g_sink_job{0};
std::atomic<uint32_t> g_lifetime_job{0};
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
std::atomic<uint32_t> g_sink_count{0};
writesentry::HitInfo g_hits[64];
uint32_t g_hit_jobs[64];
std::atomic<bool> g_hit_ready[64];
#endif
const char* g_control = "";
const char* g_control_job = "program";
const char* g_fault = "";

uint64_t Ticks() {
  LARGE_INTEGER value;
  return QueryPerformanceCounter(&value) ? static_cast<uint64_t>(value.QuadPart)
                                         : 0;
}

void Emit(const char* kind, uint32_t job, uint64_t a = 0, uint64_t b = 0,
          uint64_t c = 0) {
  std::fprintf(stderr,
               "%s{\"kind\":\"%s\",\"job\":%u,\"a\":%llu,\"b\":%llu,"
               "\"c\":%llu,\"tick\":%llu}\n",
               kPrefix, kind, job, static_cast<unsigned long long>(a),
               static_cast<unsigned long long>(b),
               static_cast<unsigned long long>(c),
               static_cast<unsigned long long>(Ticks()));
  std::fflush(stderr);
}

bool ExperimentEnabled() {
  const char* value = std::getenv("WRITESENTRY_SELECTED_WORKER_EXPERIMENT");
  return value && std::strcmp(value, "1") == 0;
}

void Stats(const char* point, uint32_t job) {
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
  const auto s = writesentry::GetStats();
  std::fprintf(stderr,
               "%s{\"kind\":\"stats\",\"point\":\"%s\",\"job\":%u,"
               "\"traps\":%llu,\"hits\":%llu,\"filtered\":%llu,"
               "\"dumps\":%llu,\"arms\":%llu,\"disarms\":%llu}\n",
               kPrefix, point, job,
               static_cast<unsigned long long>(s.traps),
               static_cast<unsigned long long>(s.hits),
               static_cast<unsigned long long>(s.filtered),
               static_cast<unsigned long long>(s.dumps),
               static_cast<unsigned long long>(s.arms),
               static_cast<unsigned long long>(s.disarms));
#else
  std::fprintf(stderr,
               "%s{\"kind\":\"stats\",\"point\":\"%s\",\"job\":%u,"
               "\"value\":null}\n",
               kPrefix, point, job);
#endif
  std::fflush(stderr);
}

__declspec(noinline) uint64_t SelectedStore(volatile uint64_t* address) {
  const uint64_t value = *address;
  *address = value;
  _ReadWriteBarrier();
  return value;
}

__declspec(noinline) uint64_t UnselectedStore(volatile uint64_t* address) {
  const uint64_t value = *address;
  *address = value + 1;
  _ReadWriteBarrier();
  return value;
}

struct Worker {
  HANDLE ready = nullptr;
  HANDLE request = nullptr;
  HANDLE done = nullptr;
  HANDLE thread = nullptr;
  DWORD id = 0;
  bool selected = false;
  bool stop = false;
  volatile uint64_t* address = nullptr;
  uint64_t value = 0;

  static DWORD WINAPI Run(void* parameter) {
    auto* worker = static_cast<Worker*>(parameter);
    worker->id = GetCurrentThreadId();
    SetEvent(worker->ready);
    for (;;) {
      if (WaitForSingleObject(worker->request, INFINITE) != WAIT_OBJECT_0)
        return 1;
      if (worker->stop) return 0;
      worker->value = worker->selected ? SelectedStore(worker->address)
                                       : UnselectedStore(worker->address);
      SetEvent(worker->done);
    }
  }

  void Start(bool is_selected) {
    selected = is_selected;
    ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    request = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    done = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (ready && request && done)
      thread = CreateThread(nullptr, 0, &Run, this, 0, nullptr);
    if (thread) WaitForSingleObject(ready, 10000);
  }

  bool Inject(uint64_t address_value) {
    address = reinterpret_cast<volatile uint64_t*>(address_value);
    if (!thread || !address) return false;
    SetEvent(request);
    return WaitForSingleObject(done, 10000) == WAIT_OBJECT_0;
  }

  void Stop() {
    stop = true;
    if (request) SetEvent(request);
    if (thread) {
      WaitForSingleObject(thread, 10000);
      CloseHandle(thread);
    }
    if (ready) CloseHandle(ready);
    if (request) CloseHandle(request);
    if (done) CloseHandle(done);
    thread = nullptr;
  }
};

Worker g_selected;
Worker g_unselected;
bool g_workers_started = false;

#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
void ObservationSink(const writesentry::HitInfo& hit) {
  const uint32_t slot = g_sink_count.fetch_add(1, std::memory_order_relaxed);
  if (slot < 64) {
    g_hits[slot] = hit;
    g_hit_jobs[slot] = g_sink_job.load(std::memory_order_acquire);
    g_hit_ready[slot].store(true, std::memory_order_release);
  }
}

void DrainHits() {
  const uint32_t count =
      std::min(g_sink_count.load(std::memory_order_acquire), 64u);
  for (uint32_t i = 0; i < count; ++i) {
    if (!g_hit_ready[i].load(std::memory_order_acquire)) continue;
    const auto& hit = g_hits[i];
    std::fprintf(stderr,
                 "%s{\"kind\":\"hit\",\"job\":%u,\"tid\":%u,\"rip\":%llu,"
                 "\"address\":%llu,\"written\":%llu,\"previous\":%llu}\n",
                 kPrefix, g_hit_jobs[i], hit.thread_id,
                 static_cast<unsigned long long>(hit.trapped_rip),
                 static_cast<unsigned long long>(hit.address),
                 static_cast<unsigned long long>(hit.written_value),
                 static_cast<unsigned long long>(hit.previous_value));
  }
  std::fflush(stderr);
}
#endif  // V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH

const char* JobName(ParserObservationKind kind) {
  return kind == ParserObservationKind::kProgram ? "program" : "function";
}

bool ControlMatches(ParserObservationKind kind) {
  return g_control[0] != '\0' && std::strcmp(g_control_job, JobName(kind)) == 0;
}

void ConfigureFault(uint32_t tid) {
#if defined(WRITESENTRY_FAULT_TESTS)
  if (std::strcmp(g_fault, "open") == 0) {
    writesentry::internal::ConfigureTestFault(
        writesentry::internal::TestFault::kOpenThread, 1, 0, tid);
  } else if (std::strcmp(g_fault, "readback") == 0) {
    writesentry::internal::ConfigureTestFault(
        writesentry::internal::TestFault::kReadback, 1, 0, tid);
  }
#else
  (void)tid;
#endif
}

}  // namespace

struct ParserObservationScope::State {
  ParserObservationKind kind;
  const void* parser;
  const void* stream;
  uint64_t cursor;
  uint32_t job;
  bool armed = false;
  writesentry::WriteSentryError arm_result =
      writesentry::WriteSentryError::kNotArmed;
  writesentry::CoverageReport coverage{};

  State(ParserObservationKind kind, const void* parser, const void* stream,
        uint64_t cursor, uint32_t job)
      : kind(kind), parser(parser), stream(stream), cursor(cursor), job(job) {}
};

ParserObservationScope::ParserObservationScope(ParserObservationKind kind,
                                               const void* parser,
                                               const void* stream,
                                               uint64_t cursor_address) {
  if (!g_collect.load(std::memory_order_acquire)) {
    state_ = nullptr;
    return;
  }
  const uint32_t job = g_next_job.fetch_add(1) + 1;
  state_ = new State(kind, parser, stream, cursor_address, job);
  g_lifetime_job.store(job, std::memory_order_release);
  g_sink_job.store(job, std::memory_order_release);
  if (kind == ParserObservationKind::kProgram)
    g_program_entries.fetch_add(1);
  else
    g_function_entries.fetch_add(1);
  Emit("entry", job, reinterpret_cast<uint64_t>(parser),
       reinterpret_cast<uint64_t>(stream), cursor_address);

#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
  writesentry::SetDumpSink(&ObservationSink);
  Stats("S0", job);
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_ARM)
  if (!g_selected.id) {
    Emit("arm-error", job, cursor_address, 0, 0);
    return;
  }
  ConfigureFault(g_selected.id);
  writesentry::SelfWatchSpec spec{};
  spec.address = cursor_address;
  spec.size = sizeof(uint64_t);
  spec.pattern.kind = writesentry::PatternKind::AnyChange;
  spec.action = writesentry::HitAction::kDump;
  spec.scope = writesentry::ThreadScope::kSelectedThreads;
  writesentry::ThreadArmResult result;
  const uint32_t selected_tid = static_cast<uint32_t>(g_selected.id);
  state_->arm_result = writesentry::ArmSelfWatchOnThreads(
      spec, &selected_tid, 1, &result, 1, &state_->coverage);
  state_->armed = state_->arm_result == writesentry::WriteSentryError::kOk ||
                  state_->arm_result ==
                      writesentry::WriteSentryError::kPartialCoverage;
  std::fprintf(stderr,
               "%s{\"kind\":\"arm\",\"job\":%u,\"result\":%u,"
               "\"discovered\":%u,\"verified\":%u,\"exited\":%u,"
               "\"selected\":%lu}\n",
               kPrefix, job, static_cast<unsigned>(state_->arm_result),
               state_->coverage.threads_discovered,
               state_->coverage.threads_verified, state_->coverage.threads_exited,
               g_selected.id);
#endif
#else
  (void)cursor_address;
#endif
}

ParserObservationScope::~ParserObservationScope() {
  if (!state_) return;
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_ARM)
  if (state_->armed) {
    writesentry::WriteSentryError result = writesentry::WriteSentryError::kOk;
    for (int attempt = 0; attempt < 3; ++attempt) {
      result = writesentry::DisarmSelfWatch(state_->cursor);
      if (result != writesentry::WriteSentryError::kPartialCoverage &&
          result != writesentry::WriteSentryError::kBusy)
        break;
    }
    const auto second = writesentry::DisarmSelfWatch(state_->cursor);
    Emit("disarm", state_->job, static_cast<unsigned>(result),
         static_cast<unsigned>(second), state_->coverage.threads_exited);
  }
#endif
  g_sink_job.store(0, std::memory_order_release);
  Emit("scope-exit", state_->job);
  delete state_;
}

void ParserObservationScope::OnInitialized() {
  if (state_) Emit("R0", state_->job);
}

void ParserObservationScope::OnParseComplete() {
  if (!state_) return;
  const uint32_t job = state_->job;
  Emit("R1", job);
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_WATCH)
  DrainHits();
  Stats("S1", job);
#if defined(V8_ENABLE_WRITESENTRY_SELECTED_WORKER_ARM)
  if (ControlMatches(state_->kind)) {
    Worker* worker = std::strcmp(g_control, "unselected") == 0
                         ? &g_unselected
                         : &g_selected;
    const bool completed = worker->Inject(state_->cursor);
    const uint64_t begin = reinterpret_cast<uint64_t>(
        worker->selected ? &SelectedStore : &UnselectedStore);
    Emit("control", job, completed ? 1 : 0, worker->value, begin);
    Emit("control-rip-range", job, begin, begin + 512,
         worker->selected ? 1 : 0);
  }
  DrainHits();
  Stats("S2", job);
#endif
#endif
}

ParserObservationLifetimeMarker::~ParserObservationLifetimeMarker() {
  const uint32_t job = g_lifetime_job.load(std::memory_order_acquire);
  if (!job) return;
  g_destructions.fetch_add(1);
  Emit("stream-destroyed", job);
  g_lifetime_job.store(0, std::memory_order_release);
}

void NoteParserBackgroundEntry() {
  if (g_collect.load(std::memory_order_acquire)) {
    g_background_entries.fetch_add(1);
    Emit("background-entry", 0);
  }
}

void ParserObservationWorkersEnter() {
  if (!ExperimentEnabled()) return;
  g_control = std::getenv("WRITESENTRY_SELECTED_WORKER_CONTROL");
  if (!g_control) g_control = "";
  if (const char* job = std::getenv("WRITESENTRY_SELECTED_WORKER_CONTROL_JOB"))
    g_control_job = job;
  if (const char* fault = std::getenv("WRITESENTRY_SELECTED_WORKER_FAULT"))
    g_fault = fault;
  g_selected.Start(true);
  g_unselected.Start(false);
  g_workers_started = true;
  Emit("workers", 0, g_selected.id, g_unselected.id);
}

void ParserObservationWorkersExit() {
  if (!g_workers_started) return;
  g_selected.Stop();
  g_unselected.Stop();
  g_workers_started = false;
}

void ParserObservationHostEnter() {
  if (!ExperimentEnabled()) return;
  g_collect.store(true, std::memory_order_release);
  g_next_job.store(0);
  g_program_entries.store(0);
  g_function_entries.store(0);
  g_background_entries.store(0);
  g_destructions.store(0);
  Emit("H0", 0);
}

void ParserObservationHostExit() {
  if (!g_collect.load(std::memory_order_acquire)) return;
  Emit("H1", 0, g_program_entries.load(), g_function_entries.load(),
       g_background_entries.load());
  Emit("destructions", 0, g_destructions.load());
  g_collect.store(false, std::memory_order_release);
}

}  // namespace v8::internal

#endif  // selected-worker or parser timing
