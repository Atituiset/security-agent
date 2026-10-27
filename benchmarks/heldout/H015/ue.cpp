#include <cstdint>
#include <string>
#include <vector>

enum class CallState { IDLE, INCOMING_RINGING, ESTABLISHED };

struct CallDialog {
 CallState state = CallState::IDLE;
 std::string peer;
 uint32_t call_id = 0;
 int kind = 0;
};

static std::vector<CallDialog> dialogs;
static void end_dialog(CallDialog &d);

static CallDialog *find_dialog_by_kind(int kind) {
 for (auto &d : dialogs) {
  if (d.kind == kind && d.state == CallState::ESTABLISHED) return &d;
 }
 for (auto &d : dialogs) {
  if (d.kind == kind) return &d;
 }
 return nullptr;
}

void end_call() {
 CallDialog *d = nullptr;
 for (auto &x : dialogs) {
  if (x.state == CallState::ESTABLISHED) { d = &x; break; }
 }
 if (d == nullptr) d = find_dialog_by_kind(1);
 if (d == nullptr) d = find_dialog_by_kind(2);
 if (d != nullptr) end_dialog(*d);
}
