int *produce_cached() {
 static int value = 7;
 return &value;
}
int *produce_empty() {
 return nullptr;
}
int inspect(int kind) {
 int *(*produce)() = kind ? produce_cached : produce_empty;
 int *p = produce();
 return *p;
}
