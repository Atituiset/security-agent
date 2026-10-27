extern int *acquire();
#define READ(p) (*(p))
int inspect() {
 return READ(acquire());
}
