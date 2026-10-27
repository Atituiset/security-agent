bool usable(const int *p);
int inspect() {
 int *p = nullptr;
 if (!usable(p)) return 0;
 return *p;
}
