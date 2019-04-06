/*
  program used to restart a checkpointed process

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
*/

/*!
 * \file restart.cpp
 * - Author: Alejandro Cabrera
 * - Date: August, 2008
 * - Brief: Uspace impl. of restart process.
 * - Modifications:
 *  - Added commentary to ease future modfication.
 *  - Updating code to make it compilable.
 * - Added doxygen-style documentation.
 */

/* CPP includes */
#include <iostream>
#include <fstream>
#include <vector>
#include <list>
#include <string>

/* C includes */
#include <unistd.h>
#include <signal.h>
#include <wait.h>
#include <fcntl.h>
#include <termios.h>
#include <cstdio>
#include <cstdlib>
#include <asm/page.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/tcp.h>
#include <errno.h>

/* Other includes */
#include "ckpt.h"

/* Using decls. */
using std::cerr;
using std::cout;
using std::endl;
using std::string;
using std::list;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::ios;

int n_procs = 0;
int n_children = 0;
pid_t notify = 0;

/*!
 * \struct ps_node
 * \brief A node in the process tree.
 */
struct ps_node {
  int tree_level;   ///< parent 0; child 1
  string filename;
  string cwd;
  vector<struct open_files> openfiles;
  vector<string> openfilenames;
};

/*!
 * \struct pipe_node
 * \brief Represents a pipe-file. 
 */
struct pipe_node {
  int inode; // inode for the pipe: id
  int fd[2];
};

vector<struct ps_node> tree;
list<struct pipe_node> pipes;

/*!
 * \brief Open a file with specified fd.
 * @param[in] fd File descriptor to try to open.
 * @param[in] filename Name of said file..
 * @param[in] flags Flags to pass to open() call.
 * @param[in] mode Mode to open file.
 * @return fd - if successful. Else, fatal erro occured.
 */
int open_file_forced(int fd, const char *filename, int flags, int mode) 
{
  
  /*! \todo Cleanup resources if open_file_forced fails. */
  int ret;

  ret=open(filename, flags, mode);
  if (ret==-1) {
    cerr<<"Cannot open file "<<filename<<endl;
    perror("open");
    cerr<<"Can't restart!"<<endl;
    exit(-1); 
  }

  if (ret==fd)
    return ret;

  if (dup2(ret, fd) < 0)
    perror("can't dup2");

  close(ret);
  return fd;
}

/*!
 * \brief Is it safe to open this file?
 * 
 * A file is safe to open if it is not /dev/tty or /dev/pts and it's fd >= 3.
 * @return 1 - safe, 0 - unsafe.
 */
inline bool open_safe(int fd, const char *filename) 
{
  return (fd >= 3 || (strncmp(filename, "/dev/tty", 8) && (strncmp(filename, "/dev/pts", 8))));
}   

/*!
 * \brief move the pointer to the right position (open_files struct arrays)
 * and return number of open files.
 * @param[out] f Filestream representing the open file.
 * @return -1 - error, >=0 , number of open files.
 */
int get_open_files(ifstream& f) 
{
  struct header hdr;
  /*! \todo Properly read-in struct header fields from ifstream. L156 */
  f.read(&hdr, sizeof(hdr));

  if (strncmp(hdr.signature, "CKPT", 4)) {
    cerr<<"Not a valid checkpoint file!"<<endl;
    return -1;
  }
  
  // skip memory info
  f.seekg(sizeof(memory), ios::cur);

  // vm areas
  int i;
  vector<struct segments> seg;
  seg.resize(hdr.num_segments);  
      
  /*! \todo Properly read-in struct segments fields from ifstream. */
  for (i = 0; i < hdr.num_segments; i++)
    f.read(&seg[i], sizeof(struct segments));
  
  f.seekg(((f.tellg()+PAGE_SIZE-1)/PAGE_SIZE) * PAGE_SIZE);

  // skip the segment data - we don't need it now
  int skip = 0;
  for (i = 0; i < hdr.num_segments; i++)
    if (!seg[i].shared)
      skip += seg[i].vm_end-seg[i].vm_start;
  
  // skip registers
  struct pt_regs regs;
  skip += sizeof(struct pt_regs);
  
  f.seekg(skip, ios::cur);
  
  struct open_files_hdr open_files_hdr;
  /*! \todo Properly read-in struct open_files_hdr fields from ifstream. */
  f.read(&open_files_hdr, sizeof(open_files_hdr));

  if (f)
    return open_files_hdr.number_open_files;
  else
    return -1;  
}

/*!
 * \brief Build the process tree.
 * @param[out] node Process tree to build.
 * @return false - failure, true otherwise.
 */
bool build_ps(struct ps_node * node) 
{
  ifstream f(node->filename.c_str());
  if (!f) {
    cerr<<"can't open file "<<node->filename<<endl;
    return false;
  }
  
  int n_open = get_open_files(f);

  if (n_open < 0)
    return false;

  if (n_open == 0)
    return true;

  node->openfiles.resize(n_open);
  node->openfilenames.resize(n_open);
  
  char buffer[512];
  for (int i = 0; i < n_open; ++i) {
    f.read(&(node->openfiles[i]), sizeof(struct open_files));
    if (node->openfiles[i].type == CKPT_FILE) {
      f.read(buffer, node->openfiles[i].entry_size);
      node->openfilenames[i] = buffer;
    }
    else {
      f.seekg(node->openfiles[i].entry_size, ios::cur);
      node->openfilenames[i] = "";
    }
  }

  // now we save cwd
  int size;
  f.read(&size, sizeof(int));
  char cwd[PATH_MAX+1];
  f.read(cwd, size);
  node->cwd = cwd;
}

/*!
 * \brief Open all the pipes related to the process tree. 
 * @param[out] pipes Pipes related to the process tree.
 * @param[in] ps Process tree.
 * @return Fatal if pipe() fails.
 */
void build_pipes(list<struct pipe_node>& pipes, const vector<struct ps_node>& ps) 
{
  for (int k = 0; k < ps.size(); k++) {
    // walk the whole ps (for each process)
    for (int i = 0; i < ps[k].openfiles.size(); i++) {
      const struct open_files& files = ps[k].openfiles[i];
    
      // check if it's already in the pipes vector
      if (files.type == CKPT_PIPE) {
	list<struct pipe_node>::iterator iter = pipes.begin();

	for (; iter != pipes.end(); ++iter) {
	  if (iter->inode == files.u.pipes.inode)
	    break;
	}

	if (iter == pipes.end()) {
	  // not found, add it
	  struct pipe_node node;
	  node.inode = files.u.pipes.inode;
	  // open pipes
	  if (pipe(node.fd) < 0)
	    perror("Can't open pipe");
	  else
	    pipes.push_back(node);
	}
      }
    }	
  }
}

/*!
 * \brief Re-opens all files related to a process tree.
 * @param[in] node Process tree with open files information.
 * @return Fatal if dup2 fails.
 */
void do_open_files(const struct ps_node* node) 
{
  for (int i = 0; i < node->openfiles.size(); i++) {
    const struct open_files *openfile = &node->openfiles[i];

    if (openfile->type == CKPT_DUP) {
      if (dup2(openfile->u.dup.dupfd, openfile->fd) != openfile->fd)
	perror("dup");
    }
    else if (openfile->type == CKPT_FILE &&
	     open_safe(openfile->fd, node->openfilenames[i].c_str())) {
	     open_file_forced(openfile->fd, node->openfilenames[i].c_str(),
			      openfile->u.file.flags, openfile->u.file.mode);    
	     }
  }
}

/*!
 * \brief  All the pipes have been opened.
 * - check fds
 * - if not mine, close;
 * - if mine, dup it  
 * @param[in] pipes Pipes possibly associated with this process node.
 * @param[in] node Process node.
 * @return Fatal if dup2() fails.
 */
void do_open_pipes(const list<struct pipe_node>& pipes,
	      const struct ps_node * node) 
{
  list<struct pipe_node>::const_iterator iter = pipes.begin();
  for (; iter != pipes.end(); iter++) {

    // check whether this is my pipe
    int i;
    const struct open_files * files;
    
    for (i = 0; i < node->openfiles.size(); i++) {
      files = &(node->openfiles[i]);
      if (files->type == CKPT_PIPE && iter->inode == files->u.pipes.inode)
	break; // it's my pipe
    }
    
    if (i < node->openfiles.size()) {
      // yes it is mine
      if (files->u.pipes.rdwr) {
	// fd[1] is mine
	close(iter->fd[0]);
	if (iter->fd[1] != files->fd) {
	  if (dup2(iter->fd[1], files->fd)<0)
	    perror("dup2 error");
	  close(iter->fd[1]);
	}
      }
      else {
	close(iter->fd[1]);
	if (iter->fd[0] != files->fd) {
	  if (dup2(iter->fd[0], files->fd)<0)
	    perror("dup2 error");
	  close(iter->fd[0]);
	}
      }      
    }
    else {
      // not mine; close them
      close(iter->fd[0]);
      close(iter->fd[1]);
    }      
  }
}

#if 0
/*!
 * \brief Debugging function used to print a process tree.
 * @param[in] tree Process tree to print.
 */
void print_tree(const vector<struct ps_node>& tree) 
{
  vector<struct ps_node>::const_iterator iter = tree.begin();
  for (; iter != tree.end(); iter++) {
    cerr<<(iter->tree_level ? "Child":"Parent")<<'\t'<<iter->filename<<endl;
    for (int i = 0; i<iter->openfiles.size(); i++) {
      cerr<<"File "<<iter->openfiles[i].fd<<": ";
      if (iter->openfiles[i].type == CKPT_FILE)
	cerr<<iter->openfilenames[i]<<endl;
      else {
	cerr<<"Pipe ["<<iter->openfiles[i].u.pipes.inode<<"] ";
	if (iter->openfiles[i].u.pipes.rdwr)
	  cerr<<'W';
	else
	  cerr<<'R';
	cerr<<endl;
      }
    }
  }
}
#endif
/*!
 * \brief Function to handle SIGUSR1.
 * @param[in] signo Number of signal received.
 */
static void sig_handler(int signo) 
{
  if (signo == SIGUSR1) {
    cerr<<getpid()<<": received notification"<<endl;
    if (--n_procs == 0) {
      // all the childern have restarted
      cerr<<getpid()<<": activating all"<<endl;
      kill(0, SIGCONT); // send to the whole process group - no harm
    }
  }
}

/*!
 * \brief Builds path by prefixing cwd/ to path arg.
 * @param[out] path Incomplete path to be built.
 */
void get_full_path(string& path) 
{
  if (path[0] != '/') {
    char buffer[PATH_MAX+1];
    char * cwd = getcwd(buffer, PATH_MAX+1);	
    path = string(cwd) + '/' + path;
  }
}

#ifdef RECOVER_TERMIOS
/*!
 * \brief Loads termios from serial file.
 * @param[in] termfile Filename for termios data.
 * @param[out] cur_term Terminal to set based on file data.
 * @return true - success, false - failure, fatal tcXattr() fails.
 */
bool load_termios(const char *termfile, struct termios *cur_term) 
{
  bool setterm = false;
  // save/set termios
  if (isatty(STDIN_FILENO)) {
    
    cout<<"saving current terminal configuraiton"<<endl;

    if (tcgetattr(STDIN_FILENO, cur_term) < 0)
      perror("tcgetattr");    
    else {
      //      string termfile = string(base_filename)+".term";
      ifstream termf(termfile);
      struct termios new_term;
      
      if (termf) {
	termf.read(&new_term, sizeof(struct termios));
	
	if (termf.tellg() == sizeof(struct termios)) {
	  
	  cout<<"setting current terminal configuraiton"<<endl;
	  
	  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) < 0)
	    perror("tcsetattr");
	  else
	    setterm = true;
	}
	termf.close();
      }
      else
	cerr<<"can't open "<<termfile<<endl;
    
    }
  }
  else {
    cerr<<"not a tty"<<endl;
  }

  return setterm;
}

/*!
 * \brief Restores previous terminal configuration.
 * @param[out] term Terminal to be restored.
 * @return fatal - tcsetattr() fails.
 */
void restore_termios(struct termios *term) 
{
  cout<<"restoring previous terminal configuration"<<endl;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, term) < 0)
    perror("tcsetattr");
}
#endif

int main (int argc, char **argv) 
{
  int ret;
  int ckpttype = 0;
  bool rawfile = false;
  bool stopped = false;
  int i;
  string base_filename;
  struct termios cur_term;
  bool setterm = false;

  if (argc<2) {
    cout<<argv[0]<<" [-r, --raw] [-t, --stop] <filename>"<<endl;
    return 1;
  }

  for (i = 1; i < argc; i++)
    if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--raw"))
      ckpttype = CHECK_SINGLE, rawfile = true;
    else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--stop"))
      stopped = true;
    else
      base_filename = argv[i];

  ifstream treefile;
  
  if (! rawfile) {    

    treefile.open((base_filename + ".tree").c_str(), ios::in|ios::bin);
    
    if (!treefile) {
      perror("can't open treefile");
      return 1;
    }

    // read in types
    string type;
    getline(treefile, type);

    if (type == CHECK_SINGLE_STRING)
      ckpttype = CHECK_SINGLE;
    else if (type == CHECK_FAMILY_STRING)
      ckpttype = CHECK_FAMILY;
    else if (type == CHECK_CHILDONLY_STRING)
      ckpttype = CHECK_CHILDONLY;
  }

  if (ckpttype == CHECK_SINGLE) {
    treefile.close();
    // get full path so that we can chdir freely
    get_full_path(base_filename);
      
    // directly restart
    struct ps_node single_node;
    single_node.tree_level = 1;
    single_node.filename = base_filename;
    build_ps(&single_node);
    do_open_files(&single_node);

#ifdef RECOVER_TERMIOS    
    setterm = load_termios((string(base_filename)+".term").c_str(), &cur_term);
#endif

    chdir(single_node.cwd.c_str()); // change cwd

    int ret = restart(base_filename.c_str(), 0, stopped?RESTART_STOP:0);
    perror("restart failed");
#ifdef RECOVER_TERMIOS    
    if (setterm)
      restore_termios(&cur_term);
#endif
    return 1;
  }
              
  // build process tree - currently 2 levels
  
  struct ps_node node;
  
  while (treefile) {
    getline(treefile, node.filename);
    if (node.filename.size() == 0)
      continue;
    node.tree_level = 1;
    // get full path so that we can chdir freely
    get_full_path(node.filename);
    tree.push_back(node);
    build_ps(&(*tree.rbegin()));
  }

  treefile.close();
  
  build_pipes(pipes, tree);  
  // print
  list<struct pipe_node>::const_iterator pipeiter = pipes.begin();
  for (; pipeiter != pipes.end(); pipeiter++)
    cerr<<"pipe ["<<pipeiter->inode<<"] : R "<<pipeiter->fd[0]
	<<", W "<<pipeiter->fd[1]<<endl;

  n_procs = tree.size();
  n_children = (ckpttype == CHECK_CHILDONLY ? tree.size() : tree.size()-1); // how many childern
  notify = getpid();
  
  if (n_children < 1) {
    cerr<<"too few processes"<<endl;
    return 1;
  }

  cerr<<n_procs<<" processes"<<endl;
  tree[n_procs].tree_level = 0; // the last is parent  

  //  print_tree(tree);

  // hook signal
  if (!stopped && (signal(SIGUSR1, sig_handler) == SIG_ERR)) {
    cerr<<"Can't catch SIGUSR1!"<<endl;
    return 1;
  }

#ifdef RECOVER_TERMIOS  
  setterm = load_termios((string(base_filename)+".term").c_str(), &cur_term);
#endif
  
  pid_t pid;
  if ((pid = fork()) < 0) {
    perror("can't fork");

#ifdef RECOVER_TERMIOS
    if (setterm)
      restore_termios(&cur_term);
#endif
    
    return 1;
  }
  else if (pid == 0) {

    // child of grandfather - actually the parent for the restarted group
    signal(SIGUSR1, SIG_DFL);
    
    cerr<<"parent forked: "<<getpid()<<endl;

    cerr<<n_children<<" children"<<endl;

    int child;
    
    for (child = 0; child< n_children; child++) {
      pid_t chpid;

      // check whether there are pipes between father and this child

      if ((chpid = fork()) < 0) {
	perror("can't fork");
	return 1;
      }
      else if (chpid == 0) {
	// child	
	cerr<<"child "<<child<<" forked: "<<getpid()<<endl;
	cerr<<"restarting from "<<tree[child].filename<<endl;
	do_open_pipes(pipes, &tree[child]);
	do_open_files(&tree[child]);
	chdir(tree[child].cwd.c_str());

	ret = restart(tree[child].filename.c_str(), notify, // notify parent
		      (stopped?0:RESTART_NOTIFY)|RESTART_STOP);
	perror("restart failed");
	return 1;
      }
    }

    if (ckpttype == CHECK_CHILDONLY) {
      while (n_procs--)
	wait(NULL);
    }
    else {
      child = tree.size()-1;
      do_open_pipes(pipes, &tree[child]);
      do_open_files(&tree[child]);
      chdir(tree[child].cwd.c_str());
      
      restart(tree[child].filename.c_str(), 0, // notify parent
	      (stopped?0:RESTART_NOTIFY)|RESTART_STOP);      
      perror("restart failed");
      return 1;
    }
    
    return 0;
    
  }

  wait(NULL); // grandfather

#ifdef RECOVER_TERMIOS
  if (setterm)
    restore_termios(&cur_term);
#endif
  
  cout<<"group ended"<<endl;

  return 0;
}
  





