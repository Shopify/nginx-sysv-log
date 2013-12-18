#include <sys/msg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

struct msqmsg {
  long mtype;
  char mtext[1024];
};

static char* lol = "{\"not\": \"json\", \"event_scope\": \"what\", \"event_partition_key\": \"1\"}";

int main()
{
  int msqid = msgget(0xDEADC0DE, 0666 | IPC_CREAT);
  if (msqid < 0) {
    perror("msgget fail");
  }

  char *meh;

  size_t size = 1024 * 1024 * sizeof(char);
  struct msqmsg *data = malloc(size);
  strcpy(data->mtext, lol);
  data->mtype=1;

  ssize_t ret;

  setvbuf(stdout, NULL, _IONBF, 0);

  printf("Waiting on log MQ at 0xDEADC0DE\n");
  for (;;) {
    usleep(1000);
    // ssize_t msgrcv(int, void*, size_t, long, int)
    ret = msgsnd(msqid, data, ((int)strlen(lol)) + 8, IPC_NOWAIT);
    if (ret < 0) {
      printf("error :( -- %d %d\n", errno, msqid);
    } else {
      printf(".");
    }

  }
}
