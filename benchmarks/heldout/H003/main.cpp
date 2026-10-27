#include "util.h"
int inspect() {
 int *p = nullptr;
 return *with_fallback(p);
}
