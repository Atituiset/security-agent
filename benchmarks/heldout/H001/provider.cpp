int *acquire(int mode) {
 static int value = 7;
 if (mode > 0) return nullptr;
 return &value;
}
