struct Handle { int operator*() const { return 7; } };
int inspect() {
 Handle h; return *h;
}
