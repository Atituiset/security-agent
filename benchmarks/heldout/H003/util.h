#ifndef UTIL_H
#define UTIL_H
inline int *with_fallback(int *p) {
 static int fallback = 7;
 return p ? p : &fallback;
}
#endif
