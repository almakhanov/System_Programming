/*
  This program dumps the information of a checkpointed file

  CRAK, Checkpoint/Restart As a Kernel module, is a Linux checkpoing/restart
  package.  It works for Linux kernel 2.2.x/i386.

  Copyright (C) 2000-2001 Hua Zhong, huaz@cs.columbia.edu
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

  This work originally started from epckpt Project, thanks to him:
  http://www.cs.rochester.edu/~edpin/epckpt

  but has been almost completely restructured and rewritten.
*/

/*!
 * \file dump.cpp
 * - Author: Alejandro Cabrera
 * - Date: August, 2008
 * - Brief: Dumps data stored in a ckpt file.
 * - Modifications:
 *  - Added commentary to ease future modfication.
 *  - Updating code to make it compilable.
 * - Added doxygen-style documentation.
 */

/* CPP includes */
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>

/* C includes */
#include <cstdio>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <asm/page.h>
#include <linux/tcp.h>

/* Other includes */
#include "ckpt.h"

/* Using decls. */
using std::cerr;
using std::cout;
using std::endl;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::setw;
using std::hex;
using std::dec;

/*! \todo Possibly break main into functions to read different portions
  of ckpt file? */

int main(int argc, char**argv) {

  /* Arg check */
  if (argc != 2) {
    cout<<"Usage: "<<argv[0]<<" file"<<endl;
    return 1;
  }

  /* Open for binary input */
  ifstream f(argv[1], ios::in|ios::binary);
  if (!f) {
    perror("can't open file");
    return 1;
  }

  // dump header
  struct header hdr;

  /*! \todo Need to read in struct header fields separately. 
    This can be accomplished by using fstream objects. L85 */
  f.read(&hdr, sizeof(hdr));

  if (strncmp(hdr.signature, "CKPT", 4)) {
    cerr<<"Not a valid checkpoint file!"<<endl;
    return 1;
  }
  
  cout<<"Version : "<<hdr.major_version<<'.'<<hdr.minor_version<<endl
      <<"Segments: "<<hdr.num_segments<<endl
      <<"Syscall : "<<(hdr.in_sys_call ? "Yes" : "No")<<endl
      <<"PID     : "<<hdr.pid<<endl
      <<"User ID : "<<hdr.uid<<'\t'<<hdr.euid<<'\t'<<hdr.suid<<'\t'<<hdr.fsuid<<endl
      <<"GroupID : "<<hdr.gid<<'\t'<<hdr.egid<<'\t'<<hdr.sgid<<'\t'<<hdr.fsgid<<endl;

  cout<<endl<<"Name    : "<<hdr.comm<<endl<<endl;

  cout.setf(ios::uppercase);
  cout.fill('0');

  // dump memory info
  struct memory mem;
  /*! \todo Need to read in struct memory fields separately. 
    This can be accomplished by using fstream objects. L108 */
  f.read(&mem, sizeof(mem));

  cout<<"code : "<<hex<<setw(8)<<mem.start_code<<'\t'<<setw(8)<<mem.end_code<<endl
      <<"data : "<<setw(8)<<mem.start_data<<'\t'<<setw(8)<<mem.end_data<<endl
      <<"brk  : "<<setw(8)<<mem.start_brk<<'\t'<<setw(8)<<mem.brk<<endl
      <<"arg  : "<<setw(8)<<mem.arg_start<<'\t'<<setw(8)<<mem.arg_end<<endl
      <<"env  : "<<setw(8)<<mem.env_start<<'\t'<<setw(8)<<mem.env_end<<endl
      <<endl;

  // dump vm areas
  int shared = 0;
  int i;
  vector<struct segments> seg;
  seg.resize(hdr.num_segments);

  // calculate sizes
  int code = 0, shlib = 0, priv = 0;
      
  for (i = 0; i < hdr.num_segments; i++) {
    /*! \todo Need to read in struct segment fields separately. 
      This can be accomplished by using fstream objects. L128 */
    f.read(&seg[i], sizeof(struct segments));

    cout<<"Seg "<<dec<<i
	<<": VM "<<hex<<setw(8)<<seg[i].vm_start<<" "<<seg[i].vm_end
      	<<"  OFF "<<seg[i].pgoff
	<<"  P "<<seg[i].prot<<"  F "<<seg[i].flags;

    if (seg[i].shared) {
      cout<<"  "<<seg[i].filename<<endl;
      shared++;
    }
    else {
      cout<<endl;
    }
  }

  cout<<endl;
  
  /*! \todo Check f.seekg() call at L148. */
  f.seekg(((f.tellg()+PAGE_SIZE-1)/PAGE_SIZE) * PAGE_SIZE);

  for (i = 0; i < hdr.num_segments; i++)
    if (!seg[i].shared)
      f.seekg(seg[i].vm_end-seg[i].vm_start, ios::cur);
  
  // dump registers
  struct pt_regs regs;
  /*! \todo Need to read in struct pt_regs segments separately. 
    This can be accomplished by using fstream objects. L158 */
  f.read(&regs, sizeof(regs));

  cout<<"ESP: "<<hex<<setw(8)<<regs.esp<<"\tEBP: "<<regs.ebp<<endl
      <<"ESI: "<<regs.esi<<"\tEDI: "<<regs.edi<<endl
      <<"EAX: "<<regs.eax<<"\tORIG_EAX: "<<regs.orig_eax<<endl
      <<"CS : "<<regs.xcs<<"\tDS : "<<regs.xds<<"\tEIP: "<<regs.eip<<endl
      <<"SS : "<<regs.xss<<"\tEFLAGS: "<<regs.eflags<<endl<<endl;
  cout.unsetf(ios::uppercase);
  
  // dump files
  struct open_files_hdr open_files_hdr;

  /*! \todo Need to read in struct open_files_hdr fields separately. 
    This can be accomplished by using fstream objects. L172 */
  f.read(&open_files_hdr, sizeof(open_files_hdr));
  cout<<"Files: "<<open_files_hdr.number_open_files<<endl;

  char * buffer;
  struct open_files open_files;
  for (i = 0; i < open_files_hdr.number_open_files; i++) {
    /*! \todo Need to read in struct open_files fields separately. 
      This can be accomplished by using fstream objects. */
    f.read(&open_files, sizeof(open_files));
    buffer = new char[open_files.entry_size];
    if (!buffer) {
      cerr<<"No enough memory!"<<endl;
      return 1;
    }

    if (open_files.entry_size)
      f.read(buffer, open_files.entry_size);
    
    cout<<"FD "<<dec<<open_files.fd<<'\t';

    if (open_files.type == CKPT_DUP)
      cout<<"DUP of fd "<<open_files.u.dup.dupfd<<endl;
    else if (open_files.type == CKPT_FILE)
      cout<<buffer<<"\tFLAGS: "<<hex<<open_files.u.file.flags
	  <<"\tMODE: "<<open_files.u.file.mode
	  <<"\tFPOS: "<<open_files.u.file.file_pos<<endl;
    else if (open_files.type == CKPT_PIPE)
      cout<<"PIPE "<<(open_files.u.pipes.rdwr? 'W':'R')
	  <<"\tINODE: "<<open_files.u.pipes.inode
	  <<'\t'<<open_files.entry_size<<" bytes left"
	  <<"\tLOCK: "<<open_files.u.pipes.lock<<endl;
    else {
      cout<<"UNKNOWN file type: "<<open_files.type<<endl;
    }
      
    delete buffer;
  }

  // CWD
  int size;
  f.read(&size, sizeof(int));
  char cwd[4096];
  f.read(&cwd, size);
  cout<<endl<<"Current Working Directory: "<<cwd<<endl<<endl;

  // signal
  /*! \todo Possibly add support for dumping signal data from ckpt file? L219 */ 
  
  return 0;
}



