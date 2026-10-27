int *acquire(int mode);
int inspect() {
 int *p = acquire(1);
 return *p;
}
