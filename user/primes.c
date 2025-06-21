#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define RD 0
#define WR 1

// to avoid compiler error: infinite recursion detected
void sieve(int [2]) __attribute__((noreturn));
void sieve(int lPipe[2])
{
    close(lPipe[WR]);
    int basePrime;

    if (read(lPipe[RD], &basePrime, sizeof(int)) <= 0) {
        close(lPipe[RD]);
        exit(0);
    }
    printf("prime %d\n", basePrime);

    int rPipe[2], buf;
    pipe(rPipe);
    /**
     * can also put the for loop here, but it'll be sequential processing
     */
    /*
    for (; read(lPipeRd, &buf, sizeof(int)) > 0; ) {
        if (buf % basePrime) {
            write(rPipe[WR], &buf, sizeof(int));
        }
    }
    */
    
    if (fork() == 0) {
        close(lPipe[RD]);
        sieve(rPipe);
    } else {
        close(rPipe[RD]);
        for (; read(lPipe[RD], &buf, sizeof(int)) > 0; ) {
            if (buf % basePrime) {
                write(rPipe[WR], &buf, sizeof(int));
            }
        }
        close(rPipe[WR]);
        close(lPipe[RD]);
        wait(0);
        exit(0);
    }
}

int main(int argc, char** argv)
{
    int initPipe[2];
    pipe(initPipe);

    if (fork() == 0) {
        sieve(initPipe);
    } else {
        close(initPipe[RD]);
        for (int i = 2; i <= 280; ++i) {
            write(initPipe[WR], &i, sizeof(int));
        }
        close(initPipe[WR]);
        wait(0);
        exit(0);
    }
    
}
