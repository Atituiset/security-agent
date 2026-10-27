int *acquire();
int inspect() {
 int *p = acquire();
 int *q = p;
 return *q;
}
