/*!
 * \file res.c
 * - Author: Alejandro Cabrera
 * - Date: August 2008
 * - Brief: Library interface to CRAK module. Wraps IOCTL
 *          functionality in convenient uspace functions.
 * - Modifications:
 *  - Added doxygen-style documentation.
 */
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "ckpt.h"

#define CKPT_TEST "testfile"

/*!
 * \brief IOCTL wrapper to run kernel-level restart.
 * @param[in] fd
 * @param[in] pid
 * @param[in] flags
 * @return < 0 - error, 0 - success
 */
int restart(int fd, const char * filename, int pid, int flags) {
  struct ckpt_param param;
  int ret, dev_fd;

  dev_fd = open(CKPT_DEV_FILE, O_RDONLY);
  if (dev_fd<0)
    return dev_fd;

  param.f.filename = filename;
  param.pid = pid;
  param.flags = flags;

  ret = ioctl(dev_fd, CKPT_IOCTL_RESTART, (int)&param);
  close(dev_fd);

  return ret;
}

int main()
{
  int fd, pid;

  fd = open(CKPT_TEST, O_RDWR);
  if(!fd){
    perror(CKPT_TEST);
    return -1;
  }

  printf("Restarting...\n");

  restart(fd, CKPT_TEST, getpid(), 0);

  close(fd);

  return 0;
}
