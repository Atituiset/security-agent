#include <cstdint>
#include <map>
#include <string>

struct UeContext {
 uint32_t tmsi = 0;
 std::string imsi;
 bool registered = false;
};

static std::map<uint32_t, UeContext> ue_contexts;

const UeContext *find_ue_by_imsi(const std::string &imsi) {
 for (const auto &entry : ue_contexts) {
  if (entry.second.imsi == imsi && entry.second.registered) return &entry.second;
 }
 return nullptr;
}
