#include <sys/msg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

struct msqmsg {
  long mtype;
  char mtext[1024];
};

int main()
{
  int msqid = msgget(0xDEADC0DE, 0666 | IPC_CREAT);
  if (msqid < 0) {
    perror("msgget fail");
  }

  size_t size = 1024 * 1024 * sizeof(char);
  struct msqmsg *data = malloc(size);

  ssize_t ret;

  printf("Waiting on log MQ at 0xDEADC0DE\n");
  for (;;) {
    // ssize_t msgrcv(int, void*, size_t, long, int)
    ret = msgrcv(msqid, data, size, 0, 0);
    if (ret < 0) {
      printf("error :( -- %d\n", errno);
    } else {
      printf("%s", data->mtext);
    }

  }
}
