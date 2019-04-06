/*
    Copyright (C) 2000, Hua Zhong <huaz@cs.columbia.edu>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*!
 * \file ckpt.h
 * - Modified by: Alejandro Cabrera, July 2008
 * - Updates:
 *  - #if for CONFIG_X86_PAE -> #ifdef
 *  - Commented out EXPORT_NO_SYMBOLS
 *  - ckpt_find_task_by_pid simplified. Kernel 2.6 handles concurrency issues.
 *  - NGROUPS -> 32
 *  - Added linux/swap.h to includes to fix swp_entry_t undefined error.
 *  - files_struct has new structure, fdtable, encapsulating members such as:
 *   - max_fds
 *   - fd
 *   - open_fds
 *   - Updated code to reflect this change.
 *  - Commented out groups field from header struct.
 *  - Removed "linux/swap.h": no longer exists.
 *  - Added documentation.
 *  - Standardized ioctls. Removed unimpl. ioctls.
 *  - Added int fd param to restart().
 */

#ifndef _CHECKPOINT_H
#define _CHECKPOINT_H

#define CKPT_MAJOR 1
#define CKPT_MINOR 6

#define CKPT_MINPID 350

#define RECOVER_TERMIOS

#include <asm/ptrace.h>
#include <linux/ipc.h>
#include <asm/param.h>

/* Bitwise definition:
   bit  0 = 0 - One process,          1 - All children
   bit  1 = 0 - Continue,             1 - Kill
   bit  2 = 0 - W/Shared Library,     1 - W/O Shared Library
   bit  3 = 0 - W/Common components   1 - W/O Common components
   bits 4-7 = Unused
*/
#define CKPT_PARAM_SIZE sizeof(struct ckpt_param)

#define CKPT_MAX_FILENAME		256

/* Values ckpt_param::flags can take */
#define CKPT_NOWAIT			0x01
#define CKPT_KILL			0x02
#define CKPT_NO_SHARED_LIBRARIES	0x04
#define CKPT_NO_BINARY_FILE		0x08

#define RESTART_STOP                    0x01 // STOP after restarted
#define RESTART_NOTIFY                  0x02 // Notify after restarted

/* Type of file descriptor encountered: */
#define CKPT_DUP			0
#define CKPT_FILE			1
#define CKPT_PIPE			2
#define CKPT_SOCK			3
#define CKPT_OTHER			4

/* IOCTL commands */
#define CKPT_MAGIC 0xCC

#define CKPT_IOCTL_CHECKPOINT            _IOW(CKPT_MAGIC, 1, struct ckpt_param)
#define CKPT_IOCTL_RESTART               _IOW(CKPT_MAGIC, 2, struct ckpt_param)

#define CKPT_MAX_IOC_NR 2

/* Networking ioctls un-impl.
#define CKPT_IOCTL_CHANGE_REMOTE_ADDR    102
#define CKPT_IOCTL_FREEZE_SOCK           103
#define CKPT_IOCTL_ACTIVATE_SOCK         104
*/

// the following only for debugging
#define CKPT_DEV_FILE    "/dev/ckpt"

/**
 * NR_syscalls macro removed for 2.6 kernel for x86 arch.
 * FIXME: Is there any way to query the maximum number
 * of defined syscalls in x86 arch dynamically?
 */
#define NR_syscalls 326

/*!
 * \struct ckpt_param
 * \brief Parameters for checkpoint/restart
 */
struct ckpt_param {

  union {
    int fd;
    const char * filename;
  } f;

  pid_t pid;
  int flags;
};

/*!
 * \struct ckpt_sock
 * \brief Used to encapsulate socket interaction (unused).
 */
struct ckpt_sock {
  int size;
  void * data;
};

/*!
 * \struct header
 * \brief Used to serialize a process.
 */
struct header {
  char signature[4]; ///< Identifies a CKPT file.
  int major_version;
  int minor_version;
  int num_segments; ///< Number of memory segments.
  int pid;                 ///< Process credentials.
  int uid,euid,suid,fsuid;
  int gid,egid,sgid,fsgid;
  int ngroups;
  unsigned in_sys_call;
  char comm[16];
};

/*!
 * \struct segments
 * \brief Encapsulates a region of virtual memory for a process.
 */
struct segments {
  unsigned long vm_start;     ///< Start address of a memory region.
  unsigned long vm_end; ///< End address of a memory region.
  unsigned long prot;   ///< Is this region protected?
  unsigned long flags;
  unsigned shared:1;    ///< Is this region shared?
  unsigned long pgoff;  ///< File position.
  char filename[CKPT_MAX_FILENAME];  ///< Maximum interpreter filename, for simplicity
};

/*!
 * \struct memory
 * \brief Encapsulates a region of physical memory for a process.
 */
struct memory {
  unsigned long context;
  unsigned long start_code, end_code, start_data, end_data;
  unsigned long start_brk, brk, start_stack, start_mmap;
  unsigned long arg_start, arg_end, env_start, env_end;
};

/*!
 * \struct open_files_hdr
 * \brief  Keeps track of number of files opened by a process.
 */
struct open_files_hdr {
	int number_open_files;
};

/*!
 * \struct ckpt_fdcache_struct
 * \brief Used to optimize access to recently opened files.
 */
struct ckpt_fdcache_struct {
  int fd;
  struct inode * inode;
};

/*!
 * \struct open_files
 * \brief Records information about files being used by a process.
 */
struct open_files {
  int entry_size; ///< How many bytes are we dumping after this struct
  int type; ///< CKPT_PIPE, CKPT_FILE,CKPT_SOCKET
  int fd;   ///<  Original fd
  /* \var u A union over all file types. */
  union
  {
    /*! \var dup This fd is a dup of another fd */
    struct {
      int dupfd;
    } dup;

    /*! \var pipes A pipe-file. */
    struct {
      unsigned long inode; ///< just a unique identifier of inode
      int lock; ///< Pipe lock
      unsigned blocked:1;
      unsigned rdwr:1; ///< 0 - read, 1 - write
    } pipes;

    /*! \var file An ordinary file. */
    struct {
      unsigned long int file_pos;
      unsigned long file; ///< unique identifier of struct file
      int flags;
      int mode;
      char *filename;
    } file;

    /*! \var sock A socket. */
    struct {
      int domain;
      int type;
      int protocol;
      int state;
      int reuse;
      unsigned int saddr, daddr;
      unsigned sport, dport;
      unsigned short backlog;
    } sock;
  } u;
};

#ifdef __KERNEL__

#include <net/dst.h>
#include <linux/sched.h>
#include <linux/swap.h> /* swp_entry_t */

#define FROM_KERNEL	0
#define FROM_USER	1

#define PACKET_SIZE	65536

// to be safe currently we don't allow checkpointing processes with PID
// < CKPT_MINPID.
inline int ckptable(struct task_struct * p) {
  return (p->pid > CKPT_MINPID);
}

// stolen from pgtable-?level.h

inline int ckpt_pgd_none(pgd_t pgd)		{ return 0; }
inline int ckpt_pgd_bad(pgd_t pgd)		{ return 0; }
inline int ckpt_pgd_present(pgd_t pgd)	{ return 1; }

#ifdef CONFIG_X86_PAE
/* 3level */
#define ckpt_pmd_offset pmd_offset
#else
/* 2level */
inline pmd_t *
ckpt_pmd_offset(pgd_t * dir, unsigned long address) { return (pmd_t *)dir; }
#endif

// lots of functions "grepped" from System.map
#ifdef CKPT_DO_NO_PAGE
int (*ckpt_do_no_page)(struct mm_struct * mm,
		       struct vm_area_struct * vma,
		       unsigned long address,
		       int write_access,
		       pte_t *page_table) = (void*)CKPT_DO_NO_PAGE;
#endif

#ifdef CKPT_DO_SWAP_PAGE
int (*ckpt_do_swap_page)(struct mm_struct * mm,
			 struct vm_area_struct * vma,
			 unsigned long address,
			 pte_t * page_table,
			 swp_entry_t entry,
			 int write_access) = (void*)CKPT_DO_SWAP_PAGE;
#endif

#ifdef CKPT_OPEN_NAMEI
int (*ckpt_open_namei)(int fd, const char *, int, int, struct nameidata *)
     = (void *)CKPT_OPEN_NAMEI;
#endif

// other helper funcitons

// these are just stolen from some kernel headers (unfortunately they have
// "extern" in the header so we can not directly use.  Also we need to
// worry about locking.

inline struct task_struct *ckpt_find_task_by_pid(int pid) {
  return find_task_by_vpid(pid);
}

static inline int ckpt_strncmp(const char * src, const char * dest, int size) {
  int i;
  for (i = 0; i < size; i++) {
    if (src[i] != dest[i])
      return 1;
    if (src[i] == 0)
      break;
  }

  return 0;
}

static inline void ckpt_strncpy(char * src, const char * dest, int size) {
  int i;
  for (i = 0; i < size; i++) {
    src[i] = dest[i];
  }
}

static inline int ckpt_strlen(char* str) {
  int size = 0;
  while (str[size] != 0)
    size++;

  return size;
}

/*
 * Check whether the specified task has the fd open. Since the task
 * may not have a files_struct, we must test for p->files != NULL.
 *
 * copied from linux/file.h
 */
inline struct file * fcheck_task(struct task_struct *p, unsigned int fd) {
	struct file * file = NULL;

	if (p->files && fd < p->files->fdt->max_fds)
		file = p->files->fdt->fd[fd];
	return file;
}

static inline struct inode *
ckpt_icheck_task(struct task_struct *p, unsigned int fd) {

  struct file *fdes = fcheck_task(p, fd);
  struct dentry *dent = fdes ? fdes->f_dentry : NULL;
  struct inode *inode = dent ? dent->d_inode : NULL;
  return inode;
}

#else // __USER_SPACE__

#define CHECK_SINGLE    0
#define CHECK_FAMILY    1
#define CHECK_CHILDONLY 2

#define CHECK_SINGLE_STRING    "** SINGLE **"
#define CHECK_FAMILY_STRING    "** FAMILY **"
#define CHECK_CHILDONLY_STRING "** CHILDREN ONLY **"

int checkpoint(int fd, int pid, int flags);
int restart(int fd, const char * filename, int pid, int flags);
int ckpt_ioctl(int request, int fd, int pid, int flags);

int save_termios(const char * termfilename, pid_t pid);

#endif // __KERNEL__

#endif // __CKPT_H__
