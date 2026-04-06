/*
 * null_deref.c
 * Benchmark sample: NULL_DEREFERENCE
 *
 * Infer should report a null dereference when argc == 1.
 * Triggering input: run with no arguments (argc == 1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int value;
    char *name;
} Item;

/* Returns NULL when input is negative */
Item *create_item(int v) {
    if (v < 0) {
        return NULL;           /* intentional: no item for negative values */
    }
    Item *it = (Item *)malloc(sizeof(Item));
    if (!it) return NULL;
    it->value = v;
    it->name  = strdup("default");
    return it;
}

void print_item(Item *it) {
    /* BUG: it may be NULL here */
    printf("Item: %s = %d\n", it->name, it->value);
}

int main(int argc, char *argv[]) {
    int input = -1;   /* default triggers NULL path */

    if (argc >= 2) {
        input = atoi(argv[1]);
    }

    Item *item = create_item(input);
    print_item(item);   /* NULL dereference when input < 0 */

    if (item) {
        free(item->name);
        free(item);
    }
    return 0;
}
