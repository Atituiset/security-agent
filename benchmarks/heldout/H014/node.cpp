#include <cstdint>
#include <map>
#include <string>

struct UeContext {
 uint32_t tmsi = 0;
 std::string imsi;
 bool registered = false;
};

const UeContext *find_ue_by_imsi(const std::string &imsi);

static std::map<uint32_t, uint16_t> tmsi_to_crnti;

uint16_t crnti_for_imsi(const std::string &imsi) {
 const UeContext *ctx = find_ue_by_imsi(imsi);
 if (ctx == nullptr) return 0;
 auto it = tmsi_to_crnti.find(ctx->tmsi);
 return it == tmsi_to_crnti.end() ? 0 : it->second;
}
