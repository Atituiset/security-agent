#include <vector>
std::vector<int *> &items() {
 static std::vector<int *> values = {nullptr};
 return values;
}
