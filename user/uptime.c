#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(char argc, char** argv)
{
    fprintf(1, "%d\n", uptime());
    exit(0);
}