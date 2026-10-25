#ifndef V8_PARSING_WRITESENTRY_PARSER_OBSERVER_H_
#define V8_PARSING_WRITESENTRY_PARSER_OBSERVER_H_

#include <cstdint>

#include "src/common/globals.h"

namespace v8::internal {

enum class ParserObservationKind { kProgram, kFunction };

// Independent parser markers and the optional one-selected-thread watch. The
// implementation is compiled only for the selected diagnostic build modes.
class ParserObservationScope {
 public:
  ParserObservationScope(ParserObservationKind kind, const void* parser,
                         const void* stream, uint64_t cursor_address);
  ~ParserObservationScope();
  ParserObservationScope(const ParserObservationScope&) = delete;
  ParserObservationScope& operator=(const ParserObservationScope&) = delete;

  void OnInitialized();
  void OnParseComplete();

 private:
  struct State;
  State* state_;
};

class ParserObservationLifetimeMarker {
 public:
  ParserObservationLifetimeMarker() = default;
  ~ParserObservationLifetimeMarker();
};

void NoteParserBackgroundEntry();
void ParserObservationWorkersEnter();
void ParserObservationWorkersExit();
void ParserObservationHostEnter();
void ParserObservationHostExit();

class ParserObservationWorkerScope {
 public:
  ParserObservationWorkerScope() { ParserObservationWorkersEnter(); }
  ~ParserObservationWorkerScope() { ParserObservationWorkersExit(); }
};

class ParserObservationHostScope {
 public:
  ParserObservationHostScope() { ParserObservationHostEnter(); }
  ~ParserObservationHostScope() {
    if (!completed_) ParserObservationHostExit();
  }
  void Complete() {
    ParserObservationHostExit();
    completed_ = true;
  }

 private:
  bool completed_ = false;
};

}  // namespace v8::internal

#endif  // V8_PARSING_WRITESENTRY_PARSER_OBSERVER_H_
