/*
 * buffer_overflow.c
 * Benchmark sample: BUFFER_OVERRUN / heap-buffer-overflow
 *
 * Infer should report a buffer overrun in copy_input().
 * Triggering input: argv[1] longer than 15 characters.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SMALL_BUF 16

void process(const char *src) {
    char buf[SMALL_BUF];      /* 16-byte stack buffer */
    /* BUG: no bounds check — strcpy overflows when strlen(src) >= 16 */
    strcpy(buf, src);
    printf("Processed: %s\n", buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }
    process(argv[1]);
    return 0;
}
