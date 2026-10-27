#include <vector>
std::vector<int *> &items();
int inspect() {
 int *p = items().front();
 return *p;
}
