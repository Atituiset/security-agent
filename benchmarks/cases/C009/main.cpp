int inspect() {
 int value = 7;
 int *p = &value;
 if (!p) return 0;
 p = nullptr;
 return *p;
}
