#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fs.h"
#include "user/user.h"

static char buf[512];

/**
 * copied from grep.c to support re
 */
int matchhere(char*, char*);
int matchstar(int, char*, char*);

int
match(char *re, char *text)
{
  if(re[0] == '^')
    return matchhere(re+1, text);
  do{  // must look at empty string
    if(matchhere(re, text))
      return 1;
  }while(*text++ != '\0');
  return 0;
}

// matchhere: search for re at beginning of text
int matchhere(char *re, char *text)
{
  if(re[0] == '\0')
    return 1;
  if(re[1] == '*')
    return matchstar(re[0], re+2, text);
  if(re[0] == '$' && re[1] == '\0')
    return *text == '\0';
  if(*text!='\0' && (re[0]=='.' || re[0]==*text))
    return matchhere(re+1, text+1);
  return 0;
}

// matchstar: search for c*re at beginning of text
int matchstar(int c, char *re, char *text)
{
  do{  // a * matches zero or more instances
    if(matchhere(re, text))
      return 1;
  }while(*text!='\0' && (*text++==c || c=='.'));
  return 0;
}
/** end of grep.c copy */

void find(char* path, char* target) {
    struct dirent de;
    struct stat st;
    int fd;
    char* p;

    if ((fd = open(path, 0)) < 0) {
        fprintf(2, "open %s failed\n", path);
        return;
    }
    if (fstat(fd, &st) < 0) {
        fprintf(2, "fstat %s failed\n", path);
        return;
    }

    switch (st.type) {
    case T_FILE:
        // if (strcmp(path + strlen(path) - strlen(target), target) == 0) {
        if (match(target, path)) {
            printf("%s\n", path);
        }
        break;
    case T_DIR:
        if (strlen(path) + DIRSIZ + 2 > sizeof(buf)) {
            fprintf(2, "path too long\n");
            return;
        }
        memcpy(buf, path, strlen(path));
        p = buf + strlen(path);
        *p++ = '/';
        while (read(fd, &de, sizeof(de)) == sizeof(de)) {
            if (de.inum == 0) continue;
            memmove(p, de.name, DIRSIZ);
            p[DIRSIZ] = 0;
            if (stat(buf, &st) < 0) {
                fprintf(2, "stat %s failed\n", buf);
                return;
            }
            if (strcmp(buf + strlen(buf) - 2, "/.") != 0 && 
                strcmp(buf + strlen(buf) - 3, "/..") != 0) {
                find(buf, target);
            }

        }
        break;
    }
    close(fd);
}

int main(int argc, char** argv) {

    if (argc < 3) {
        printf("not enough arguments\n");
        exit(0);
    }
    
    char target[512];
    target[0] = '/';
    strcpy(target + 1, argv[2]);
    find(argv[1], target);

    exit(0);

}
