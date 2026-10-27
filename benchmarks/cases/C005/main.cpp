int inspect() {
 int value = 7;
 int *p = nullptr, *q = p;
 p = &value;
 return *q;
}
