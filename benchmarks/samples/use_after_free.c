/*
 * use_after_free.c
 * Benchmark sample: USE_AFTER_FREE
 *
 * Infer should report a use-after-free at the print_item call.
 * Triggering input: argv[1] == "free"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int   data;
    struct Node *next;
} Node;

Node *new_node(int data) {
    Node *n = (Node *)malloc(sizeof(Node));
    if (!n) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    n->data = data;
    n->next = NULL;
    return n;
}

int main(int argc, char *argv[]) {
    Node *head = new_node(10);
    head->next = new_node(20);

    int do_free_early = 0;
    if (argc >= 2 && strcmp(argv[1], "free") == 0) {
        do_free_early = 1;
    }

    if (do_free_early) {
        free(head);   /* free head while next still referenced */
    }

    /* BUG: accessing head after free when do_free_early == 1 */
    printf("head->data = %d\n", head->data);

    if (!do_free_early) {
        free(head->next);
        free(head);
    }
    return 0;
}
