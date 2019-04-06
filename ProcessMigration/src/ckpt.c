/*
  CRAK, Checkpoint/Restart As a Kernel module, is a Linux checkpoing/restart
  package.  It works for Linux kernel 2.2.x/i386.

  Copyright (C) 2000-2001, Hua Zhong <huaz@cs.columbia.edu>
      
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

  This work originally started from Eduardo Pinheiro's epckpt Project:
  
  http://www.cs.rochester.edu/~edpin/epckpt

  but has been almost completely restructured and rewritten.

  04/22/2001:
  
  Added support for tcp/ipv4 socket (incomplete).  Using ioctl for all
  operations.
*/

/*!
 * \file ckpt.c
 * - Modified by: Alejandro Cabrera
 * - Date: August 6, 2008
 * - Updates:
 *  - Removed all networking-related headers. None used.
 *  - struct pt_regs modified since 2.4.x:
 *   - In kernel-space compilation, leading 'e' removed from reg names.
 *  - Updated code to reflect change.
 *  - Added NR_syscalls macro def, since x86 lost it.
 *  - pte_offset(dir,address) -> pte_offset_kernel(dir,address)
 *  - Added linux/swapops.h for pte_to_swp_entry().
 *  - 2.4.4: d_path(struct vfsmount *, struct d_entry *, char *, int)
 *  - 2.6.25: d_path(struct path *, char *, int *).
 *  - struct path encapsulates d_entry and vfsmount.
 *  - Commented out occurences dependent on max_fdset (removed).
 *  - Code dependent on task_struct->groups can likely be removed.
 *  - Commented out "groups" usage.
 *  - Added linux/mount.h for mntget() & mntput().
 *  - Replaced p_pptr(process_parentPointer) with parent.
 *  - Working on standardizing and updating chrdev_registration.
 *  - Updated signals: action[] found in sighand_struct, no longer signal_struct.
 *   - sig -> signal
 *   - gigmask_lock -> siglock
 *  - (WIP) Look up details on inode structures, PIPE_X changes.
 *  - (WIP) Look up details on signal architecture.
 * - Adding Doxy-style documentation
 * - Included linux/sched.h.
 * - Added task_locks. Safety not yet guaranteed.
 */

#define __CHECKPOINT__
/* The necessary header files */

/* Standard in kernel modules */
#include <linux/smp.h>
#include <linux/kernel.h>   /* We're doing kernel work */
#include <linux/module.h>   /* Specifically, a module */

/* For character devices */
#include <linux/fs.h>       /* The character device 
                             * definitions are here */
#include <linux/cdev.h>
#include <linux/binfmts.h>
#include <asm/mman.h>
#include <asm/uaccess.h> /* for KERNEL_DS and get_fs() */
#include <linux/file.h>
#include <linux/sys.h>
#include <asm/page.h>
#include "config.h"
#include "ckpt.h"

#include <linux/mount.h>
#include <linux/swapops.h>
#include <linux/sched.h>

/* verbose prinks */
const int verbose = 1;

/* performance testing */
//#define PRINT_TIME

#ifdef PRINT_TIME

#include <asm/msr.h>

typedef struct tcounter 
{
  unsigned long tlo;
  long thi;
} tcounter_t;

inline void gettsc(long long int* utime) 
{
  unsigned long Lo;
  long Hi;
  tcounter_t* tc = (tcounter_t*)utime;
  rdtsc(Lo,Hi);
  tc->tlo = Lo;
  tc->thi = Hi;
}

inline unsigned long hi_word(unsigned long long u) 
{
  unsigned long * ptr = (unsigned long *)&u;
  return *(ptr+1);
}

inline unsigned long lo_word(unsigned long long u) 
{
  unsigned long * ptr = (unsigned long *)&u;
  return *ptr;
}

#endif

#if 0
#define IS_SYS_CALL(regs)	(((regs).orig_eax>=0) && 		\
				 ((regs).eax == -ERESTARTNOHAND ||	\
				  (regs).eax == -ERESTARTSYS ||		\
				  (regs).eax == -ERESTARTNOINTR) ) 
#endif

#define IS_FD_NAMED(fdes)       ((fdes)->f_dentry->d_name.name)


static int do_checkpoint(int fd, struct task_struct * p, int flags);

static char * get_kernel_address(struct task_struct * p, struct vm_area_struct *vm, unsigned long addr);

/*!
 * \brief Whether it's inside a system call
 *        the basic idea is to get the previous two chars pointed by EIP
 *        to see whether they are 0xCD 0x80.
 * @param[in] p    Current process.
 * @param[in] regs Registers corresponding to p.
 * @return 1 - in a syscall 0 - not in a syscall.
 */
static int is_sys_call(struct task_struct *p, struct pt_regs * regs) 
{
  char *ins1, *ins2;
  if (regs->orig_ax <= 0 || regs->orig_ax > NR_syscalls)
    return 0;
  
  ins1 = get_kernel_address(p, find_vma(p->mm, regs->ip - 2), regs->ip - 2);
  ins2 = get_kernel_address(p, find_vma(p->mm, regs->ip - 1), regs->ip - 1);
  if (ins1 && ins2 && (*ins1 == (char)0xcd) && (*ins2 == (char)0x80))
    return 1;
  else
    return 0;
}

/*!
 * \brief Checkpoint process 'pid' to a descriptor pointed by 'fd'. 
 * @param fd File descriptor to save process to.
 * @param pid Process to checkpoint.
 * @param flags Checkpointing options. \see ckpt.h For flags.
 * @return 
 *  - -EBADF - Bad file descriptor.
 *  - -ESRCH - No such pid.
 *  - -EACCES - Cannot ckpt this pid.
 *  - <0 - Some other error condition.
 *  - 0 - Success.
 */
static int checkpoint(int fd, pid_t pid, int flags) 
{
  struct task_struct *p;
  struct file *f;
  int ret;
  int stop = 0;
#ifdef PRINT_TIME
  long long hr_time1, hr_time2;
  gettsc(&hr_time1);
#endif	
	
  f  = fcheck(fd);
  if (!f){
    if(verbose) printk("Error: Bad fd.");
    return -EBADF;
  }
	
  p = ckpt_find_task_by_pid(pid);
		
  if (!p){
    if(verbose) printk("Error: No such pid.");
    return -ESRCH; /* no such pid */
  }

  if (((p->uid != current->euid && p->uid != current->uid)
       && (current->uid && current->euid))
      || !ckptable(p)){
    if(verbose) printk("Error: Not accessible.");
    return -EACCES;    
  } 

  // we don't checkpoint a currently running process.
  // stop it first.	
  if (p != current) {
    send_sig(SIGSTOP, p, 0);
    stop = 1;
  }
	
  if ((ret = do_checkpoint(fd, p, flags)) != 0)
    return ret;

  if (stop)
    send_sig(SIGCONT, p, 0);
	
  if (flags & CKPT_KILL)
    send_sig(SIGKILL, p, 0); /* kill it if possible */

#ifdef PRINT_TIME
  gettsc(&hr_time2);
  printk("checkpoint %s: %lu, %lu\n", p->comm, hi_word(hr_time2 - hr_time1), lo_word(hr_time2 - hr_time1));
#endif	
	
  return 0;
}

static inline int inside(unsigned long a,
			 unsigned long b,
			 unsigned long c) 
{
  return (c <= b) && (c >= a);
}

/*!
 * \brief Checks to see if a given memory segment is valid.
 *
 * Checking details:
 * - (valid) Check if vm_start lies within start_code and end_code region.
 * - (valid) Check if vm_start lies within end_code and end_data
 * - (valid) Check if vm_start lies within end_data and brk.
 * - (valid) Check if vm_start lies within start_stack abd 0xc0000000.
 * - (valid) Check if regs.sp (stack pointer) lies within vm_start and vm_end.
 * - Else, invalid.
 * @param[in] regs
 * @param[in] mm
 * @param[in] vma
 * @return 1 - valid, 0 - invalid.
 */
static inline int valid_memory_segment (struct pt_regs regs, struct mm_struct *mm, 
					struct vm_area_struct *vma) 
{ 
  if (inside(mm->start_code, mm->end_code, vma->vm_start))
    return 1;
  else if (inside(mm->end_code, mm->end_data, vma->vm_start))
    return 1;
  else if (inside(mm->end_data, mm->brk, vma->vm_start))
    return 1;
  else if (inside(mm->start_stack, 0xC0000000, vma->vm_start))
    return 1;
  else if (inside(vma->vm_start, vma->vm_end, regs.sp))
    return 1;
  else
    return 0;	
}

/*!
 * \brief Write a packet of data to a file.
 *
 * \todo Add impl. details.
 * @param[out] f Pointer to file to be written to.
 * @param[out] buf Incoming data to write.
 * @param[in] len Number of bytes to write.
 * @param[in] last_pkt Number of the last packet to write.
 * @param[in] flag FROM_[USER|KERNEL].
 * @return 0 - success, <0 - error.
 */
static int pack_write (struct file *f, char *buf, int len, int last_pkt, int flag) 
{
  static char *pack = NULL;
  static long pos = 0;
  int ret, to_copy, wrtn = 0;

  // Allocate the packet.
  if (pack==NULL)	{
    pack=(char*)kmalloc(PACKET_SIZE, GFP_KERNEL);
    if (!pack)
      return -1;
  }	

  // While there's data to copy, continue.
  while (len>0) {

    // Determine amount of data to copy this round.
    to_copy = (len>(PACKET_SIZE-pos))?(PACKET_SIZE-pos):(len);

    // Determine source of data and procedure to follow.
    if (flag==FROM_USER)
      copy_from_user(&(pack[pos]), buf+wrtn, to_copy);
    else
      ckpt_strncpy(&(pack[pos]), buf+wrtn, to_copy);

    // Update progress vars.
    pos += to_copy;
    len -= to_copy;
    wrtn +=to_copy; 

    // If we've reached the last data.
    if ( (pos==PACKET_SIZE) || (last_pkt) )	{
      mm_segment_t fs = get_fs();

      set_fs(KERNEL_DS);
      ret = f->f_op->write(f, pack, pos, &(f->f_pos));	
      set_fs(fs);
      if (ret!=pos)
	return ret;
				
      pos = 0;
      if (last_pkt)
	{
	  kfree(pack);
	  pack = NULL;
	}
    }
  }
	
  if ( (last_pkt) && (pack!=NULL) ) {
    if (pos!=0) {
      mm_segment_t fs = get_fs();

      set_fs(KERNEL_DS);
      wrtn = f->f_op->write(f, pack, pos, &f->f_pos);
      set_fs(fs);
    }
    kfree(pack);
    pack = NULL;
    pos = 0;
  }	
  return wrtn;
}


/*!
 * Converts user address -> kernel address. Addr should be aligned by page.
 * Refer to handle_pte_fault() in mm/memory.c
 *
 * @param[in] p    Process to checkpoint.
 * @param[in] vm   Memory region for this process.
 * @param[in] addr Address to convert.
 * @return NULL - failure, kernel address otherwise.
 */
static char * get_kernel_address(struct task_struct * p,
				 struct vm_area_struct *vm,
				 unsigned long addr) 
{
  pgd_t *pgd;
  pmd_t *page_middle;
  pte_t *pte;
	  
  pgd = pgd_offset(p->mm, addr);

  if (ckpt_pgd_none(*pgd)) {
    printk("none pgd: %08lx\n", (unsigned long)pgd);
    return NULL;
  }

  if (ckpt_pgd_bad(*pgd)) {
    printk("bad pgd: %08lx\n", (unsigned long)pgd);
    pgd_ERROR(*pgd);
    return NULL;
  }
	
  page_middle = ckpt_pmd_offset(pgd, addr);
  if (pmd_none(*page_middle))
    return NULL;

  if (pmd_bad(*page_middle)) {
    printk("Bad page middle entry %08lx\n", pmd_val(*page_middle));
    return NULL;
  }

  // hmmm..currently I am not dealing with swap-in for non-present pmd..
  /*! \todo Deal with swapping of non-present pmd. L383 */
  if (!pmd_present(*page_middle)) {
    printk("Non-present page middle entry %08lx\n", pmd_val(*page_middle));
    return NULL;
  }

  pte = pte_offset_kernel(page_middle,addr);

  if (pte == NULL) {
    printk("NULL pte\n");
    return NULL;
  }
  
  /*! \bug OOPS on null pointer dereference. 
    ckpt_X_page fncs() NULL. */
  /*! \todo Ween away use of ckpt_do_X_page funcs. They no longer exist in
    kernel symbol table. Find out what they used to do and substitute their
    functionality. */
  /*
  if (!pte_present(*pte)) {
     * If it truly wasn't present, we know that kswapd
     * and the PTE updates will not touch it later. So
     * drop the lock.
    spin_lock(&p->mm->page_table_lock);
    if (pte_none(*pte)){
      ckpt_do_no_page(p->mm, vm, addr, vm->vm_flags&VM_MAYWRITE, pte);
    }
    else{
      ckpt_do_swap_page(p->mm, vm, addr, pte, pte_to_swp_entry(*pte), 0);
    }
    spin_unlock(&p->mm->page_table_lock);
  }
  */

  if (!pte_present(*pte)) {
    printk("ERROR: Page for %08lx still not present!\n", addr);
    return NULL;
  }

  return (char *) page_address(pte_page(*pte)) + (addr & ~PAGE_MASK);
}

/*!
 * Dump vm area to file.
 * @param f  File to write to.
 * @param p  Process to checkpoint.
 * @param vm Memory region of process.
 * @return 0 - always succeeds.
 */
static int dump_vm_area(struct file *f, struct task_struct * p,
			struct vm_area_struct *vm) 
{
  char * data;
  unsigned long addr = vm->vm_start;

  /* we may write to the pgtable */
  down_write(&p->mm->mmap_sem);

  while (addr < vm->vm_end) {

    data = get_kernel_address(p, vm, addr);

    if (data) {
      if ((unsigned long)data & ~PAGE_MASK)	
	printk("Warning: address %8lx not aligned!\n", (unsigned long)data);
    
      if (pack_write(f, (void*)data, PAGE_SIZE, 0, FROM_KERNEL) != PAGE_SIZE)
	printk("Warning: not all dumped\n");
    }
    else {
      printk ("Page not found! vm_start %08lx, vm_end %08lx, addr %08lx\n",
	      vm->vm_start, vm->vm_end, addr);
    }
    
    addr += PAGE_SIZE;
  }

  up_write(&p->mm->mmap_sem);
  return 0;
}  

/*!
 * Function to perform the act of checkpointing. Details follow.
 *
 * The order data is saved to fd is as follows:
 * -# Save the header structure.
 * -# Save the memory structure.
 * -# Save the segments structure.
 * -# Save the register contents.
 * -# Save file descriptors.
 * -# Save the CWD.
 * -# Save signals.
 * @param fd File to save ckpt data to.
 * @param p Task-struct containing process to ckpt.
 * @param flags Defined in ckpt.h. 
 * @return 0 - success, else - failure.
 */
int do_checkpoint(int fd, struct task_struct * p, int flags) 
{
  struct file *f;
  struct vm_area_struct *vm;
  struct header hdr;
  struct memory mem;
  struct segments seg;
  struct open_files_hdr open_files_hdr;
  struct open_files open_files;
  struct files_struct * files;
  struct pt_regs regs;
  struct path * pth;
  mm_segment_t fs;
  unsigned char no_shrlib, no_binary;
  int memleft, fds;
  int ret, i, j, filecnt;

  char * buffer = 0;
  char * line = 0;

  /*
   * This is added to cache fds that have been checked.
   * If the current fd has the same inode as a previous fd,
   * we should put it as type CKPT_DUP and recover with dup2.
   */
  int fdcache_size = 0;
  struct ckpt_fdcache_struct *fdcache = 0;

  // Allocate path now, so we won't have to later.
  pth = (struct path*) kmalloc(sizeof(struct path), GFP_KERNEL);
	
  task_lock(current);
  f = current->files->fdt->fd[fd]; 
  task_unlock(current);

  memleft = PAGE_SIZE;

  files = p->files;

  /*! \todo Investigate method to grab struct pt_regs from stack. L489 */
  regs = *(((struct pt_regs *) (2*PAGE_SIZE + (unsigned long) p)) - 1);

  // now fs is valid
  fs = get_fs();

  /* Dump the header */
  ckpt_strncpy(hdr.signature, "CKPT", 4);
  hdr.major_version = CKPT_MAJOR;
  hdr.minor_version = CKPT_MINOR;

  /* Count number of virtual memory segments. Store in i. */
  for (i=0, vm = p->mm->mmap; vm!=NULL; i++,vm = vm->vm_next); //<- semicolon

  /********************* SAVE THE HEADER ****************************/
  hdr.num_segments = i;

  task_lock(p);
  hdr.pid = p->pid;
  hdr.uid = p->uid;
  hdr.euid = p->euid;
  hdr.suid = p->suid;
  hdr.fsuid = p->fsuid;
  hdr.gid = p->gid;
  hdr.egid = p->egid;
  hdr.sgid = p->sgid;
  hdr.fsgid = p->fsgid;
  hdr.ngroups = p->group_info->ngroups;
  hdr.in_sys_call = is_sys_call(p, &regs);

  ckpt_strncpy(hdr.comm, p->comm, 16);
  task_unlock(p);
	
  no_shrlib = (flags & CKPT_NO_SHARED_LIBRARIES);
  no_binary = (flags & CKPT_NO_BINARY_FILE);
  if (verbose)
    printk("Saving header: %d segments\n",hdr.num_segments);

  // set now
  set_fs(KERNEL_DS);

  pack_write(f, (void*)&hdr, sizeof(struct header), 0, FROM_KERNEL);
  memleft -= sizeof(struct header);

  /********************* SAVE THE MEMORY ****************************/

  task_lock(p);
  mem.start_code  = p->mm->start_code;
  mem.end_code    = p->mm->end_code;
  mem.start_data  = p->mm->start_data;
  mem.end_data    = p->mm->end_data;
  mem.start_brk   = p->mm->start_brk;
  mem.brk         = p->mm->brk;
  mem.start_stack = p->mm->start_stack;
  mem.arg_start   = p->mm->arg_start;
  mem.arg_end     = p->mm->arg_end;
  mem.env_start   = p->mm->env_start;
  mem.env_end     = p->mm->env_end;
  task_unlock(p);

  if (verbose)
    printk("Saving vm structure\n");
  pack_write(f, (void*)&mem, sizeof(struct memory), 0, FROM_KERNEL);
  memleft -= sizeof(struct memory);

  // dump segments
  ret = -ENOMEM;
  buffer = (char*)__get_free_page(GFP_KERNEL);
  if (!buffer)
    goto out;
	
  if (verbose)
    printk("Saving segments\n");

  
  /********************* SAVE THE SEGMENTS ****************************/
  for (i=0, vm = p->mm->mmap; vm!=NULL; i++, vm = vm->vm_next) {
    unsigned char valid_mem;
		
    seg.vm_start = vm->vm_start;
    seg.vm_end   = vm->vm_end;
    seg.prot     = vm->vm_page_prot.pgprot;
    seg.flags    = vm->vm_flags;
    seg.shared   = 0;
    seg.pgoff   = vm->vm_pgoff;
    seg.filename[0] = 0;
	  
    valid_mem = valid_memory_segment(regs, p->mm, vm);
    if ( ((no_binary && valid_mem) || (no_shrlib && !valid_mem)) &&
	 // if this is a code segment or shared library
	 ( !(seg.flags&VM_WRITE) || (seg.flags&VM_MAYSHARE)) ) {
      // and it's not writable or it's shared
      // then we can safely map the original file
	      
      if (vm->vm_file) {
	struct path pth;
	pth.mnt = vm->vm_file->f_vfsmnt;
	pth.dentry = vm->vm_file->f_dentry;
	line = d_path(&pth, buffer, PAGE_SIZE);
	buffer[PAGE_SIZE-1] = 0;
	seg.shared = 1;
	ckpt_strncpy(seg.filename, line, CKPT_MAX_FILENAME);
      }
    }
	  
    /* Dump all segments' header */
    pack_write(f, (void*)&seg, sizeof(struct segments), 0, FROM_KERNEL);
	  
    if (memleft < sizeof(struct segments))
      memleft = PAGE_SIZE + memleft;
    memleft -= sizeof(struct segments);
  }
	
  /* Dump the padding so the header is a mutiple of a page size */
  if (memleft > 0) {
    char *padbuf;
    padbuf = (char*)kmalloc(memleft, GFP_KERNEL);
    pack_write(f, padbuf, memleft, 0, FROM_KERNEL);
    kfree(padbuf);
  }

  set_fs(fs);

  if (verbose)
    printk("Saving vm areas\n");

  for (i = 0, vm = p->mm->mmap; vm!=NULL; i++, vm = vm->vm_next) {
    unsigned char valid_mem;

    /* Dump the memory segment */
    valid_mem = valid_memory_segment(regs, p->mm, vm);

    /* Dump pages and shared libs if we are allowed to */

    if (!( ((no_binary && valid_mem) || (no_shrlib && !valid_mem)) &&
	   ( !(vm->vm_flags&VM_WRITE) || (vm->vm_flags&VM_MAYSHARE)) &&
	   vm->vm_file )) {
	    
      if (dump_vm_area(f, p, vm)) {
	ret = -EAGAIN;
	goto out;
      }
    }
  }

  set_fs(KERNEL_DS);

  /********************* SAVE THE REGISTERS ****************************/
  if (verbose)
    printk("Saving registers\n");

  if (p == current)
    regs.ax = 0; // avoid infinite loop!
  /* If we are in a system call, we must restart it */
  else if (hdr.in_sys_call) {
    regs.ip -= 2;
    regs.ax = -EINTR;
  }
	
  ret = pack_write(f, (void*)&regs, sizeof(regs), 0, FROM_KERNEL);

  /* ----------------------------------------------------------- */
  /*   The dumps on this section are optional. They might not    */
  /*   occur on some circumstances, so they all start with a     */
  /*   common heading that tells whether or not theses sections  */
  /*   are present					       */
  /* ----------------------------------------------------------- */
 	
  /* FILE SECTION */
  /* Find the open fds first */
  // copied from close_files in exit.c

  // calculate how many files are opened first

  if (verbose)
    printk("Saving file table\n");

  filecnt = j = 0;

  if (!buffer)
    buffer = (char*)__get_free_page(GFP_KERNEL);
	
  if (!buffer)
    goto out;
	
  if (verbose)
    printk("max_fds = %d\n", files->fdt->max_fds);
	
  for (;;) {
    unsigned long set;
    fds = j * __NFDBITS;	  
    if (fds >= files->fdt->max_fds)
      break;
    set = files->fdt->open_fds->fds_bits[j++];
    while (set) {
      if (set & 1) {
	if (ckpt_icheck_task(p, fds)) {
	  filecnt++;
	}
      }
	    
      fds++;
      set >>= 1;
    }
  }

  if (verbose)
    printk("%d named opened files\n", filecnt);
	
  open_files_hdr.number_open_files = filecnt;
  pack_write(f, (void*)&open_files_hdr, sizeof(struct open_files_hdr), 0, FROM_KERNEL);

  fdcache = (struct ckpt_fdcache_struct*)kmalloc(sizeof(struct ckpt_fdcache_struct)*filecnt, GFP_KERNEL);

  ret = -ENOMEM;
	
  if (!fdcache)
    goto out;
	
  /* Now we dump them */
  j = 0;
  for (;;) {
    unsigned long set;
    fds = j * __NFDBITS;	  
    if (fds >= files->fdt->max_fds)
      break;
    set = files->fdt->open_fds->fds_bits[j++];
    while (set) {
      if (set & 1) {
	struct file *fdes = fcheck_files(files, fds);
	struct dentry *dent = fdes ? fdes->f_dentry : NULL;
	struct inode *inode = dent ? dent->d_inode : NULL;
	int i;

	if (!inode)
	  goto next;
	      
	open_files.fd = fds;
	      
	// check whether this inode has appeared before
	for (i = 0; i < fdcache_size; i++) {
	  if (inode == fdcache[i].inode) {
	    // cache hit
		  
	    if (verbose)
	      printk("fd %d is a dup of fd %d\n", (int)fds, fdcache[i].fd);
	    open_files.type = CKPT_DUP;		    
	    open_files.u.dup.dupfd = fdcache[i].fd;
	    open_files.entry_size = 0;
	    pack_write(f, (void*)&open_files, sizeof(struct open_files), 0, FROM_KERNEL);		  
	    goto next;
	  }
	}

	// if not a dup, push to the cache
	fdcache[fdcache_size].fd = fds;
	fdcache[fdcache_size].inode = inode;
	fdcache_size++;
	      
	if (!inode) {
	  printk("fd %d has no entry\n", fds);
	}
	else if (S_ISSOCK(inode->i_mode)) {
	  printk("fd %d is socket - unsupported\n", fds);
	  ret = -ENOSYS;
	  goto out;
	}

	/* *** UNNAMED PIPE *** */
	/*! \todo Correct pipe dumping. Because of changes to piping impl. in Linux 2.6.11,
	  pipes now use multiple circular buffers. PIPE_X macros removed(). */

	/*
	else if (S_ISFIFO(inode->i_mode))) {

	  if (down_interruptible(PIPE_SEM(*inode))) {
	    ret = -ERESTARTSYS;
	    goto out;
	  }

	  mutex_lock(inode->i_mutex);
	
	  //	  PIPE_READERS(*inode)++;
	  ++(inode->i_pipe->readers);
		
	  open_files.type = CKPT_PIPE;
	  open_files.fd = fds;

	  open_files.u.pipes.inode = inode->i_ino; // identity
	  open_files.u.pipes.rdwr = (fdes->f_flags&O_WRONLY); 
	  open_files.entry_size = PIPE_LEN(*inode);		
	  pack_write(f, (void*)&open_files, sizeof(struct open_files), 0, FROM_KERNEL);
		
	  pack_write(f, (void*)PIPE_BASE(*inode)+PIPE_START(*inode),
		     PIPE_LEN(*inode), 0, FROM_KERNEL);

	  PIPE_READERS(*inode)--;

	  //	  up(PIPE_SEM(*inode));
	  mutex_unlock(inode->i_mutex);
	}      
	*/

	/* *** REGULAR FILE *** */
	else if (IS_FD_NAMED(fdes)) {

	  pth->mnt = mntget(fdes->f_vfsmnt);
	  pth->dentry = dget(dent);
	  line = d_path(pth, buffer, PAGE_SIZE);
	  buffer[PAGE_SIZE-1] = 0;
	  dput(pth->dentry);
	  mntput(pth->mnt);
		
	  open_files.type = CKPT_FILE;
	  open_files.fd = fds;
	  open_files.u.file.file = (unsigned long)fdes;
	  open_files.u.file.flags = fdes->f_flags;
	  open_files.u.file.mode = fdes->f_mode;
	  open_files.u.file.file_pos = fdes->f_pos;

	  open_files.entry_size = buffer + PAGE_SIZE - line;
		
	  pack_write(f, (void*)&open_files, sizeof(struct open_files), 0, FROM_KERNEL);
#if 0
	  printk("fd %d: %s (%d)\n", fds, line, open_files.entry_size);
#endif		
	  pack_write(f, (void*)line, open_files.entry_size, 0, FROM_KERNEL);

	}
	else
	  printk("Unknown file type, cannot handle\n");
      }

    next:
	    
      fds++;
      set >>= 1;
    }
  }
		
  /**************************************/
  /*             Dump CWD               */
  /**************************************/
  {
    int size;

    pth->dentry = dget(p->fs->pwd.dentry);
    pth->mnt = mntget(p->fs->pwd.mnt);
    line = d_path(pth, buffer, PAGE_SIZE);
    buffer[PAGE_SIZE-1] = 0;
    size = buffer+PAGE_SIZE-line;

    dput(pth->dentry);
    mntput(pth->mnt);
    pack_write(f, (void *)&size, sizeof(size), 0, FROM_KERNEL);
    pack_write(f, (void *)line, size, 0, FROM_KERNEL);

    if (verbose)
      printk("saving cwd: %s\n", line);
  }

  /* *************************************************************** */
  /* **	Dump the signal handler section.                        ** */
  /* *************************************************************** */

  if (verbose)
    printk("Saving signal handlers\n");
  {
    sigset_t blocked;
    struct signal_struct sig;
    unsigned long * signal = (unsigned long *)&p->pending.signal;

    spin_lock_irq(&p->sighand->siglock);
    	  
    	  
    // ignore SIGSTOP/SIGCONT	  
    if ((_NSIG_WORDS == 2 && signal[0]) & ~(0x60000L || signal[1]))
      printk("pending signals not saved: %08lx %08lx\n",
	     signal[0], signal[1]);
	  
    blocked = p->blocked;
    sig = *(p->signal);
	  
    spin_unlock_irq(&p->sighand->siglock);
	  
    pack_write(f, (void*)&blocked, sizeof(blocked), 0, FROM_KERNEL);
    pack_write(f, (void*)&sig, sizeof(sig), 0, FROM_KERNEL);
  }
	
  ret = 0;
	
 out:	
  pack_write(f, NULL, 0, 1, FROM_KERNEL); /* last packet */

  free_page((unsigned long)buffer);
  kfree(fdcache);	
  kfree(pth);

  /* THE END */
  set_fs(fs);
	
  return ret;
}

/* ************************************************************************** */

/* -------------------------------------------------------------------------- */

/*!
 * Refer to flush_old_exec in kernel for details. Seems to flush
 * all traces of a previous execution so a new one may take it's place.
 * 
 * @param[in] filename Parameter for linux_binprm.
 * @param[in] file     Parameter for linux_binprm.
 * @return 0 - Success, error otherwise.
 */
static int ckpt_flush_old_exec(char * filename, struct file * file) 
{
  // we use the funciton kernel already has
  struct linux_binprm bin;
  memset(&bin, 0, sizeof(bin));
  bin.filename = filename;
  bin.file = file;
  return flush_old_exec(&bin);
}

/*!
 * Extracts flags from vm_flags value.
 * @param[in] vm_flags Integer value containing flags.
 * @return Refer to linux/mm.h and code for details.
 */
static inline unsigned long get_mmap_flags(unsigned short vm_flags) 
{

  return MAP_FIXED |
    (vm_flags & VM_MAYSHARE? MAP_SHARED : MAP_PRIVATE) |
    (vm_flags & VM_GROWSDOWN) |
    (vm_flags & VM_DENYWRITE) |
    (vm_flags & VM_EXECUTABLE);
}

/*!
 * Opens a file set to private.
 * @param[in] filename File to open.
 * @param[in] flags    Binary, append, etc.
 * @param[in] mode     Read, write, etc.
 * @return NULL - failure, otherwise an open file.
 */
static struct file * open_private_file(int fd, const char *filename, int flags, int mode) 
{
  struct file * file = NULL;
  struct dentry *d;
  struct nameidata nd;
    
  /*! \bug NULL pointer error in here somewhere. */
  if (ckpt_open_namei(fd, filename, flags, 0, &nd))
    goto out;  
  
  file = (struct file*)kmalloc(sizeof(struct file), GFP_KERNEL);
  if (!file){
    if (verbose) printk("not file");
    goto out;
  }
  
  d = nd.path.dentry;

  if (IS_ERR(d)){
    if (verbose) printk("is err d");
    goto out;
  }
  
  if (!d->d_inode || !d->d_inode->i_op
      || !d->d_inode->i_fop){
    if (verbose) printk("d stuff");
    goto out; 
  }

  /* Does dentry_open set vfsmnt? */
  if (verbose) printk("before dentry open");
  file->f_vfsmnt = nd.path.mnt;
  file = dentry_open(d, nd.path.mnt, mode);

 out:
  return file;
}

/*!
 *  Restart a process that was once checkpointed.
 *  This call does not return on success. Instead, it replaces the
 *  currently running process with the checkpointed code, similar
 *  to what exec() does.
 *
 * @param[in] fname File to read process data from.
 * @param[in] pid   
 * @param[in] flags ckpt_flags. Refer to "ckpt.h".
 * @return 
 */
static int restart(int fd, const char * fname, pid_t pid, int flags) 
{
  struct file *f = NULL;
  struct header hdr;
  struct segments seg;
  struct memory mem;
  struct open_files open_files;
  struct open_files_hdr open_files_hdr;
  struct pt_regs regs;
  char * filename = NULL;
  int ret, i, skippad;
  mm_segment_t fs;
  unsigned long int oldsize;
  int err;

#ifdef PRINT_TIME
  long long hr_time1, hr_time2;
  gettsc(&hr_time1);
#endif

  fs = get_fs();

  filename = getname((char*)fname);

  err = PTR_ERR(filename);
  if (IS_ERR(filename))
    goto out;

  err = -ENOMEM;
	
  f = open_private_file(fd, filename, 1, 1);

  // get dentry from filename (see file_open in fs/open.c)

  /* Error checks on file initialization from above call. */
  if (!f || !f->f_op || !f->f_op->read) {
    printk("null pointer\n");
    goto out;
  }	
	
  f->f_pos = 0;

  ckpt_flush_old_exec(filename, f);
	
  set_fs(KERNEL_DS);
	
  /* Read in the header */
  ret = f->f_op->read(f, (char*)&hdr, sizeof(hdr), &f->f_pos);
  
  if ((ret != sizeof(hdr)) || ckpt_strncmp(hdr.signature, "CKPT", 4) ||
      hdr.major_version != CKPT_MAJOR ||
      hdr.minor_version != CKPT_MINOR) {
    printk("Invalid checkpoint file\n");
    goto out;
  }

  if (((hdr.uid != current->euid && hdr.uid != current->uid)
       && (current->uid && current->euid))) {
    err = -EACCES;
    goto out;
  }

  /* restore uid/gid */	
  if (current->uid == 0 || current->euid == 0) {
    current->uid = hdr.uid;
    current->euid = hdr.euid;
    current->suid = hdr.suid;
    current->fsuid = hdr.fsuid;
    current->gid = hdr.gid;
    current->egid = hdr.egid;
    current->sgid = hdr.sgid;
    current->fsgid = hdr.fsgid;
    current->group_info->ngroups = hdr.ngroups;
  }
	
  if (verbose)
    printk("Reading header: %d segments\n",hdr.num_segments);

  // restore command name
  ckpt_strncpy(current->comm, hdr.comm, 16);
	
  putname(filename); /* free up the name we allocated */
  filename = NULL;

  current->state=TASK_INTERRUPTIBLE;

  /* Read the memory mapping */
  if (verbose)
    printk("Restoring vm structure\n");
	
  f->f_op->read(f, (void*)&mem, sizeof(struct memory), &f->f_pos);

  current->mm->start_code  = mem.start_code;
  current->mm->end_code    = mem.end_code;
  current->mm->start_data  = mem.start_data;
  current->mm->end_data    = mem.end_data;
  current->mm->start_brk   = mem.start_brk;
  current->mm->brk         = mem.brk;
  current->mm->start_stack = mem.start_stack;
  current->mm->arg_start   = mem.arg_start;
  current->mm->arg_end     = mem.arg_end;
  current->mm->env_start   = mem.env_start;
  current->mm->env_end     = mem.env_end;

  /* Calculate the number of bytes (round to pages) to skip after headers */
  skippad = (hdr.num_segments * sizeof(struct segments)) + sizeof(struct header) + sizeof(struct memory); 
  if (skippad%PAGE_SIZE!=0)
    skippad = (skippad/PAGE_SIZE + 1)*PAGE_SIZE;	

  oldsize = 0;

  if (verbose)
    printk("Restoring vm areas\n");

  /* Map all the segments */
  for (i=0; i<hdr.num_segments; i++) {
    unsigned long size;
    unsigned long mmap_prot, mmap_flags;

    set_fs(KERNEL_DS);
    err = -EIO;
    f->f_op->read(f, (void*)&seg, sizeof(struct segments), &f->f_pos);

    size = seg.vm_end - seg.vm_start;

    set_fs(fs);

    /* *** MMAP *** */
    mmap_prot = seg.flags & 7;
    mmap_flags = get_mmap_flags(seg.flags);
    if (!seg.shared) {
      mmap_flags &= ~VM_EXECUTABLE;
    }
	  
    if (!seg.shared) {

      ret = do_mmap(f, seg.vm_start, size, mmap_prot,
		    mmap_flags|MAP_FIXED, skippad+oldsize);
    }
    else {
      struct file *file;
      //	    struct dentry *d;
      //	    struct nameidata nd;
      int omode = O_RDONLY;
	    
      set_fs(KERNEL_DS);
	  
      if ( (mmap_prot&PROT_WRITE) && (mmap_flags&MAP_SHARED) &&
	   !(mmap_flags&MAP_DENYWRITE))	
	omode = O_RDWR;

      //	    file = open_exec(seg.filename);
      file = open_private_file(fd, seg.filename, omode,
			       mmap_prot&PROT_WRITE? 3:1);
	    
      set_fs(fs);

      if (!(mmap_flags&MAP_PRIVATE) && !(mmap_flags&MAP_SHARED))
	mmap_flags |= MAP_PRIVATE|MAP_DENYWRITE|MAP_EXECUTABLE;

      ret = do_mmap_pgoff(file, seg.vm_start, size, mmap_prot,
			  mmap_flags|MAP_FIXED, seg.pgoff);

      if (ret != seg.vm_start)
	printk("Error in mmap %08lx!\n", seg.vm_start);
	    
      size = 0; /* We haven't used the checkpointed file! */

    }

    if (ret!=seg.vm_start) {
      printk(KERN_WARNING "Restart: Mapping error at map #%d.",i); 
      printk(KERN_WARNING "Sent %lX and got %X (%ld)\n", seg.vm_start, ret, (signed long)ret);
      err = -EFAULT;
      goto out;
    }

    oldsize += size;
  }
	
  set_fs(KERNEL_DS);

  /* Skip all segments and go to the next section in the file */
  if (!f->f_op->llseek)
    f->f_pos = oldsize + skippad;
  else
    f->f_op->llseek(f, oldsize+skippad, 0);
	
  /* Read in the registers to our stack, so when this system call
     exits we jump to our new code */
  if (verbose)
    printk("Restoring registers\n");

  f->f_op->read(f, (void*)&regs, sizeof(regs), &f->f_pos);
  *(((struct pt_regs *) (2*PAGE_SIZE + (unsigned long) current)) - 1)
    = regs;	

  /*   FILES   */
  if (verbose)
    printk("Restoring file table\n");
	
  err = -EIO;
	
  if (f->f_op->read(f, (void*)&open_files_hdr, sizeof(struct open_files_hdr), &f->f_pos) 
      != sizeof(struct open_files_hdr)) {
    goto out;
  }

  for (i=0; i<open_files_hdr.number_open_files; i++) {
    struct file *fdes;
    struct inode *inode;

    if (f->f_op->read(f, (void*)&open_files, sizeof(struct open_files), &f->f_pos) 
	!= sizeof(struct open_files)) {
      err = -EIO;
      goto out;
    }
	  
    fdes = current->files->fdt->fd[open_files.fd];
    inode = fdes->f_dentry->d_inode;
	  
    switch (open_files.type) {
    case CKPT_DUP:
    case CKPT_FILE:	    
      /* We don't need to do anything, since 
	 someone (restart) has already dupped/opened the 
	 file. We just skip this entry.
      */

      f->f_pos+=open_files.entry_size;
      break;
      /*! \todo Handle the case of restarting a pipe file. Refer to do_checkpoint() 
	for details.*/
       
      /*      
    case CKPT_PIPE:
      if ( !fdes ||
	   !S_ISFIFO(inode->i_mode) ) {
	printk("WARNING: restart: fd %d was not previously open or is not a pipe!!!\n",open_files.fd);

	send_sig(SIGKILL, current, 0);
	goto out;
      }
	    
      // Now read the information left in the pipe
      if (open_files.entry_size>0) {
	f->f_op->read(f, (void*)PIPE_BASE(*inode), open_files.entry_size, &f->f_pos);
	PIPE_LEN(*inode)+=open_files.entry_size;
      }
      break;
      */
    case CKPT_SOCK:
      printk("Socket not supported\n");
      err = -ENOSYS;
      goto out;
    }
  }

  /**************************************/
  /*                CWD                 */
  /**************************************/

  // has been changed to in user space, so skip
  {
    int size;
    f->f_op->read(f, (void*)&size, sizeof(int), &f->f_pos);
    f->f_pos += size; /* skip cwd */
  }

  /******************/
  /*    SIGNALS     */
  /******************/

  if (verbose)
    printk("Restoring signal handlers\n");
  {
    sigset_t blocked;
    struct sighand_struct sighand;
    int i;

    f->f_op->read(f, (void*)&blocked, sizeof(sigset_t), &f->f_pos);
    f->f_op->read(f, (void*)&sighand, sizeof(sighand), &f->f_pos);

    spin_lock_irq(&current->sighand->siglock);	 
	  
    current->blocked = blocked;
    for (i = 0; i < _NSIG; i++)
      current->sighand->action[i] = sighand.action[i];
	  
    spin_unlock_irq(&current->sighand->siglock);
  }

  err = 0;
	
  /* THE END */
  /*! \todo Verify file handler f is memory-unmapped. Refer to L1290 next line for details. */
  /* don't free file handler 'f', because it's mmaped somewhere. I hope munmap will get rid of it */
	
  current->state = TASK_RUNNING;

  if (flags & RESTART_STOP) {
    if (verbose)
      printk("Currently stopped\n");

    send_sig(SIGSTOP, current, 0);
  }

  if (verbose)
    printk("*** RESTART: done ***\n");

  if (hdr.in_sys_call)
    err = regs.orig_ax; 	// returns the number of the original syscall.

  else
    err = 0;
	
 out:
  if (err < 0 && verbose)
    printk("restart error: %d\n", -err);
	
  set_fs(fs);

  if (filename)
    putname(filename);

  if (flags & RESTART_NOTIFY) {
    // we need to notify someone

    //	  struct task_struct * p = current->p_pptr;
    struct task_struct * p = current->parent;
    // if pid == 0 notify parent

    if (pid > 0)
      p = ckpt_find_task_by_pid(pid);

    if (p) {

      if (verbose)
	printk("Notifying process %d\n", p->pid);

      send_sig(SIGUSR1, p, 0); // let him know!
    }
  }
#ifdef PRINT_TIME
  gettsc(&hr_time2);
  printk("restart %s: %lu, %lu\n", current->comm, hi_word(hr_time2 - hr_time1), lo_word(hr_time2 - hr_time1));
#endif	
	
  return err;		
}

/* Device Declarations **************************** */

/* The name for our device, as it will appear 
 * in /proc/devices */
#define DEVICE_NAME "ckpt"

static int ckpt_open(struct inode *inode, 
		     struct file *file) {
  return 0;
}

static int ckpt_release(struct inode *inode, 
			struct file *file) {
  return 0;
}

/*!
 * ioctl impl. for checkpoint. Primary means to interact with device.
 */
int ckpt_ioctl(struct inode * inode_i, struct file * file,
	       unsigned int cmd, unsigned long arg) {
  struct ckpt_param param;

  /* Quick error checking. */
  if(_IOC_TYPE(cmd) != CKPT_MAGIC) return -ENOTTY;
  if(_IOC_NR(cmd) > CKPT_MAX_IOC_NR) return -ENOTTY;
  
  // arg is the pointer to ckpt_param
  if (copy_from_user(&param, (struct ckpt_param *)arg, sizeof(struct ckpt_param)))
    return -EFAULT;

  if (verbose)
    printk("pid is %d, cmd is %d\n", param.pid, cmd);
  
  // do checkpoint/restart here
  switch(cmd){
  case CKPT_IOCTL_CHECKPOINT:
    printk("Running a checkpoint...\n");
    return checkpoint(param.f.fd, param.pid, param.flags);
    break;
  case CKPT_IOCTL_RESTART:
    return restart(param.f.fd, param.f.filename, param.pid, param.flags);
    break;
  default:
    return -EINVAL;    
  }
}

/* Module Declarations ***************************** */

static int major;

struct file_operations ckpt_fops = {
 owner:		THIS_MODULE,
 ioctl:		ckpt_ioctl,
 open:		ckpt_open,
 release:	ckpt_release,
};

struct cdev ckpt_cdev;

static void setup_ckpt_cdev(dev_t devno)
{
  int err;
  
  cdev_init(&ckpt_cdev, &ckpt_fops);
  ckpt_cdev.owner = THIS_MODULE;
  ckpt_cdev.ops = &ckpt_fops;
  err = cdev_add(&ckpt_cdev, devno, 1);
  
  if(err)
    printk(KERN_WARNING "Error %d adding ckpt device", err);
}


static int ckpt_init(void) 
{
  int result;
  dev_t dev;

  result = alloc_chrdev_region(&dev, 0, 1, DEVICE_NAME);  
  if(result < 0){
    printk("Error allocating device ckpt w/ major %d.\n", major);
    return result;
  }

  major = MAJOR(dev);
  setup_ckpt_cdev(dev);

  return 0;
}

static void ckpt_cleanup(void) 
{
  cdev_del(&ckpt_cdev);
  unregister_chrdev_region(MKDEV(major,0), 1);
}

module_init(ckpt_init);
module_exit(ckpt_cleanup);

MODULE_LICENSE("GPL");
