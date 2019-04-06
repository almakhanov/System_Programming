/*
  Checkpoint specified processes

  CRAK, Checkpoint/Restart As a Kernel module, is a Linux checkpoing/restart
  package.  It works for Linux kernel 2.2.x/i386.

  Copyright (C) 2000-2001, Hua Zhong <huaz@cs.columbia.edu>
  
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

  04/22/01:

  Added termios support.
*/

/**
 * \file ck.cpp
 * - Author: Alejandro Cabrera
 * - Date: August, 2008
 * - Brief: Checkpoints a process.
 * - Modifications:
 *  - Added documentation to make it easier to understand
 *    source.
 *  - Working on removing unnecessary clutter/includes.
 *  - Updated source to make it compilable. 
 *  - Changed a few instances of char[] -> string.
 *  - Removed various includes.
 *  - Added Doxygen-style documentaion.
 */

/* CPP includes */
#include <iostream>
#include <fstream>
#include <sstream>
#include <list>
#include <string>

/* C includes */
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <termio.h>

/* Other includes. */
#include "ckpt.h"

/* Using decls. */ 
using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::list;
using std::ifstream;
using std::ofstream;
using std::ios;

#define PROC_ROOT_DIR "/proc"
#define PROC_PROCESS_STAT_FILE "stat"

/*!
 * \brief Returns the parent pid.
 * @param[in] pid The process id of a child process.
 * @return The process id of the parent.
 */
pid_t get_ppid(pid_t pid) 
{
  
  char filen[256];
  int i;
  
  sprintf(filen, PROC_ROOT_DIR "/%d/" PROC_PROCESS_STAT_FILE, pid);
  ifstream ifile(filen);
  
  if (!ifile) {
    cerr << "can't open file " << filen << endl;
    return false;
  }

  int i_dummy, ppid;
  char c_dummy;
  string s_dummy;
  ifile>>i_dummy>>s_dummy>>c_dummy>>ppid;

  return ppid;
}


/*!
 * \brief Read all the pids from /proc.
 *
 * @param[out] plist Used to store /proc pids.
 * @param[in] ppid Parent pid.
 * @return false - failure, true otherwise.
 */
bool get_children (list<pid_t>& plist, const pid_t ppid) 
{
  // opendir
  DIR* p_dir = opendir(PROC_ROOT_DIR);
  if (!p_dir) {
    perror("Can't open "PROC_ROOT_DIR);
    return false;
  }

  int pid;
  
  plist.resize(0);
  struct dirent * this_entry;  
  while ((this_entry = readdir(p_dir)) != NULL) {
    int pid = atoi(this_entry->d_name);
    if (pid <= 0)
      continue;

    struct stat status;
    string path = string(PROC_ROOT_DIR "/") + this_entry->d_name;
    if (stat(path.c_str(), &status) != 0) {
      cerr<<"failed getting stat from "<<this_entry->d_name
	  <<". errno "<<errno<<endl;
      continue;
    }    
    // it should be a directory
    else if (S_ISDIR(status.st_mode) && (get_ppid(pid) == ppid))
      plist.push_back(pid), cout<<pid<<endl;
  }

  //  cout<<plist.size()<<" processes"<<endl;
  closedir(p_dir);
  return true;
    
}

#ifdef RECOVER_TERMIOS
/*!
 * \brief Serialize terminal ios.
 * @param[in] termfilename File name identifying terminal.
 * @param[in] pid Process id that spawned term.
 * @return 1 - Nothing done, 0 - Terminal ckpt-ed.
 */
int save_termios(const char * termfilename, pid_t pid) 
{
  
  // first we need to know which terminal that process is using
  // on Linux it's /proc/xxxx/fd/0
  char tty_fd_path[256];
  char tty_name[256];
  snprintf(tty_fd_path, 255, "/proc/%d/fd/0", pid);
  int tty_fd;
  int linklen = 0;

  if ((linklen = readlink(tty_fd_path, tty_name, 255)) > 0) {
    tty_name[linklen] = 0;

    if (strncmp(tty_name, "/dev", 4))
      return 1;
    
    if ((tty_fd = open(tty_name, O_RDONLY)) < 0) {
      perror(tty_name);
    }       
    else if (isatty(tty_fd)) {
      struct termios term;
      cout<<"saving terminal configuration for "<<tty_name<<endl;
      
      if (tcgetattr(tty_fd, &term) < 0) {
	perror("tcgetattr");
	return 0;
      }
      
      ofstream termfile(termfilename, ios::out);
      /*! \todo Properly serialize term_ios. Currently, save_termios does nothing. */
      //      termfile.write(&term, sizeof(struct termios));
    }
  }
  else
    perror("read link");
  
}
#endif

int main(int argc, char** argv) 
{

  int pid, ret, i;
  string base_filename = "checkpoint";
  int ckpttype = 0;
  int option = CKPT_KILL | CKPT_NO_SHARED_LIBRARIES | CKPT_NO_BINARY_FILE;

  pid = 0;

  /* Parse command line args */
  for (i = 1; i < argc; i++)
    if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--all"))
      ckpttype = CHECK_FAMILY;
    else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--child"))
      ckpttype = CHECK_CHILDONLY;
    else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--run"))
      option &= ~CKPT_KILL;
    else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--shlib"))
      option &= ~CKPT_NO_SHARED_LIBRARIES;
    else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--binary"))
      option &= ~CKPT_NO_BINARY_FILE;
    else if (pid>0)
      base_filename = argv[i];
    else
      pid = atoi(argv[i]);

  /* Program usage */
  if (pid <= CKPT_MINPID) {
    cout<<argv[0]<<" [-a|-c] [-r -s -b] pid <filename>"<<endl;
    cout<<"    -a, --all   : checkpoint this pid and all its children"<<endl
	<<"    -c, --child : checkpoint all its children only"<<endl
	<<"    -r, --run   : continue running after checkpoint"<<endl
	<<"    -s, --shlib : dump shared libraries"<<endl
	<<"    -b, --binary: dump code segments"<<endl
	<<"   pid: currently should >"<<CKPT_MINPID<<endl;
    return 1;
  }
    
#ifdef RECOVER_TERMIOS
  save_termios((base_filename+".term").c_str(), pid);
#endif
    
  list<pid_t> pid_list;

  /*
   * If we're running a checkpoint:
   * -get the child processes.
   * -Too many, and it's an error.
   */
  if (ckpttype) {
    get_children(pid_list, pid);
    if (pid_list.size() > 999) {
      cerr<<"Too many children"<<endl;
      return 1;
    }
  }	

  /*
   * If we're checkpointing more than just the children:
   * -Get the parent.
   */
  if (ckpttype != CHECK_CHILDONLY)
    pid_list.push_back(pid); // parent be the last

  if (pid_list.size() == 0) {
    cerr<<"No process is gonna be checkpointed"<<endl;
    return 1;
  }
    
  // stop all the processes first
  if (ckpttype) {
    list<pid_t>::const_iterator iter;
    iter = pid_list.begin();
    for (; iter != pid_list.end(); iter++) {
      kill(*iter, SIGSTOP);
    }
  }
    
  string treefilename = string(base_filename) + ".tree";
  ofstream treefile(treefilename.c_str(), ios::out);

  // save type
  if (ckpttype == CHECK_FAMILY) {
    treefile<<CHECK_FAMILY_STRING<<endl;
    cout<<"checkpoint the whole family"<<endl;
  }
  else if (ckpttype == CHECK_CHILDONLY) {
    treefile<<CHECK_CHILDONLY_STRING<<endl;
    cout<<"checkpoint all the children"<<endl;
  }
  else {
    treefile<<CHECK_SINGLE_STRING<<endl;
    cout<<"checkpoint this process only"<<endl;
  }
    
  i = 1;

  /*
   * Checkpoint process.
   */
  std::stringstream read;
  for (iter = pid_list.begin(); iter != pid_list.end(); ++iter) {
    //      char filename[260];
    string filename;

    /* Create a filename to represent this process. */
    if (pid == *iter){
      filename = base_filename;
    }
    else{
      string tmp;
      filename = base_filename + ".";
      read << i;
      tmp = read.str();
      filename.append(tmp);
    }

    ++i;

    /* Checkpoint process with ID pid by writing to file. */
    int fd = open(filename.c_str(), O_WRONLY);
    cout << "checkpointing pid " << std::dec << (*iter) << " with option "
	 << std::hex << option << " to file " << filename << endl;
    ret = checkpoint(fd, *iter, option);
    fchmod(fd, 0600);
    close(fd);
		     
    /* Checkpoint: Did it succeed? */
    if (ret) {
      perror("checkpoint aborted");
      kill(*iter, SIGCONT);
      return 1;
    }
    else {
      cout<<"checkpoint succeeded"<<endl;
      treefile<<filename<<endl;
    }
  }

  /* Kill process after checkpointing. */
  if (ckpttype && !(option&CKPT_KILL)) {
    iter = pid_list.begin();
    for (; iter != pid_list.end(); iter++)
      kill(*iter, SIGCONT);
  }

  return 0;
}

