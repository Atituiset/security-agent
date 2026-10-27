extern int *acquire();
int inspect() {
 int *p = acquire();
 return *p;
}
