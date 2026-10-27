int inspect(int mode) {
 int value = 7;
 int *p = nullptr;
 if (mode > 0) p = &value;
 if (mode > 1) return 0;
 return *p;
}
