static int *current = nullptr;
int *acquire() {
 return current;
}
