int inspect(int mode) {
 int primary = 7, fallback = 3;
 int *p = mode > 0 ? &primary : nullptr;
 if (p == nullptr) p = &fallback;
 return *p;
}
