#include <memory>
int inspect() {
 std::unique_ptr<int> holder;
 int *p = holder.get();
 return *p;
}
