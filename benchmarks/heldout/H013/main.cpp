typedef int *(*producer_fn)();
extern producer_fn active_producer;
int inspect() {
 int *p = active_producer();
 return *p;
}
