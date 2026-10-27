#include "provider.h"
int inspect() {
 int *p = acquire();
 return *p;
}
