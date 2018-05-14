#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

typedef int pid_t;
static void syscall_handler (struct intr_frame *);
void syscall_halt (void);
int syscall_wait(pid_t aa);
void syscall_exit(int a);
bool syscall_remove(const char *file);
bool syscall_create(const char *file, unsigned initial_size);
pid_t syscall_exec(const char* cmd_line);
int syscall_open(const char* file);
int syscall_filesize(int fd);
int syscall_read(int fd, void* buffer, unsigned size);
int syscall_write(int fd, const void* buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);
bool check(const void *addr);
static struct currFile* findFile (int);
//struct lock files;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
 // printf ("system call!\n");
 // thread_exit (0);
  void *esp = f->esp;
  uint32_t *eax = &f->eax;
  if (!check(((int *) esp)) || !check(((int *) esp) + 1)){
	syscall_exit(-1);
  }
  int fd = *(((int *) esp) + 1);
  const char *argChar = *(((char **) esp) + 1);
  unsigned argUS = *(((unsigned *) esp) + 2);
  unsigned argUS3 = *(((unsigned *) esp) + 3);
  const void *argVoid = (void *) *(((int *) esp) + 2);
  switch(*(int*) f->esp){
  case SYS_HALT:
	//Call system call halt
  	syscall_halt();
  	break;
  case SYS_EXIT:
	{
	//Call system call exit with a status argument
	syscall_exit(fd);
	break;
	}
  case SYS_EXEC:
	{
	//Call system call execute with first argument, in this case is a command line 
	*eax = (uint32_t) syscall_exec(argChar);
  	break;
	}
  case SYS_WAIT:
	{
	//Call process_wait with argument pid from first argument
	pid_t pid = *(((pid_t *) esp) + 1);
	*eax = (uint32_t) syscall_wait(pid);
	break;
	}
  case SYS_CREATE:
	{
  	//bool check1 = check(f->esp+1);
  	//bool check2 = check(*(f->esp+1));
  	/*if(check(f->esp+1)||check(*(f->esp+1)))
  	{
  		quit();
  	}
  	else
  	{
  		char *name = (const char *)*(unsigned int *)f->esp+1;
  		unsigned int size = *((unsigned int *)f->esp+2);
  		lock_acquire(&files);
  		filesys_create(name, size);
  		lock_release(&files);
  	}*/

	//Call system call create with first argument a file and second argument the size of that file
	*eax = (uint32_t) syscall_create(argChar, argUS);
  	break;
	}
  case SYS_REMOVE:
	{
  	//check validity
  	//syscall_remove(*(f->esp+1), f);
	
	//Call system call remove with a file argument
	*eax = (uint32_t) syscall_remove(argChar);
  	break;
	}
  case SYS_OPEN:
	{
  	//check validity
  	//syscall_open(*(f->esp+1));

	//Call system call open with a file argument
	*eax = (uint32_t) syscall_open(argChar);
  	break;
	}
  case SYS_FILESIZE:
	{
	//Call system call filesize with argument file directory
	*eax = (uint32_t) syscall_filesize(fd);
	break;
	}
  case SYS_READ:
	{
	//Call system call read with arguments file directory, void buffer, and size of the buffer
	*eax = (uint32_t) syscall_read(fd, argVoid, argUS3);
	break;
	}
  case SYS_WRITE:
	{
	//Call system call write with arguments file directory, void buffer, and size of the buffer
	*eax = (uint32_t) syscall_write(fd, argVoid, argUS3);
	break;
	}
  case SYS_SEEK:
	{
	//Call system call seek with arguments file directory and position of the file
	syscall_seek(fd, argUS);
	break;
	}
  case SYS_TELL:
	{
	//Call system call tell with file directory argument
	*eax = (uint32_t) syscall_tell(fd);
	break;
	}
  case SYS_CLOSE:
	{
	//Call system call close with file directory argument
	syscall_close(fd);
	break;
	}
}
}
bool
check(const void* addr)
{
	struct thread *curr = thread_current();
	if(addr == NULL || is_kernel_vaddr(addr) || pagedir_get_page(curr->pagedir, addr) == NULL){
		return false;
	}
	
	return true;
}
static struct currFile *
findFile(int fd)
{
	struct thread *curr = thread_current();
	struct list_elem *elem;
	elem = list_begin(&curr->openfiles)
	while (elem != list_end(&curr->openfiles))
	{
		struct currFile *cF = list_entry(elem, struct currFile, elem);
		if (cF->fd == fd) return cF;
		elem = list_next(elem);
	}
	return NULL;
}
void
syscall_halt(void)
{
	shutdown_power_off();
}
int
syscall_wait(pid_t aa)
{
	return process_wait(aa);
}
void
syscall_exit(int a)
{
	//thread_current->exit_status = a;
	//thread_exit();
	//struct thread *curr = thread_current();
	thread_current()->exitStatus = a;
	thread_exit();
}
pid_t 
syscall_exec(const char *cmd_line)
{
	tid_t childTID = TID_ERROR;

	if(!check(cmd_line)) syscall_exit(-1);

	childTID = process_execute(cmd_line);
	return childTID;
}
bool 
syscall_create(const char *file, unsigned initial_size)
{
	bool retVal = false;
	if(check(file))
	{
		lock_acquire(&sys_lock);
		retVal = filesys_create(file, initial_size);
		lock_release(&sys_lock);
		return retVal;
	}
	else syscall_exit(-1);
	return retVal;
}
bool 
syscall_remove(const char *file)
{
	/*f->eax = filesys_remove(name);
	bool retVal = false;
	if(f->eax != NULL)
	{
		retVal = true;
	}
	return retVal;*/
	bool retVal = false;
	if(check(file))
	{
		lock_acquire(&sys_lock);
		retVal = filesys_remove(file);
		lock_release(&sys_lock);
		return retVal;
	}
	else syscall_exit(-1);
	return retVal;
}
int
syscall_open(const char *file)
{
	/*//acquire lock
	struct file *opened = filesys_open(file);
	if(!opened){
	//release lock
	return -1;
	}
	//release lock
	//int retVal = process_add_file(opened);
	return 0;*/
	if(check((void *) file))
	{
		struct currFile *opened = palloc_get_page (0);
		opened->fd = thread_current()->next_fd++;
		lock_acquire(&sys_lock);
		opened->file = filesys_open(file);
		lock_release(&sys_lock);
		
		if(opened->file == NULL) return -1;
		
		list_push_back(&thread_current()->openfiles, &opened->elem);
		return opened->fd;
	}
	else syscall_exit(-1);

	return -1;
}
int 
syscall_filesize(int fd)
{
	int retVal;
	if(findFile(fd) == NULL) return 0;
	lock_acquire(&sys_lock);
	retVal = file_length(findFile(fd)->file);
	lock_release(&sys_lock);
	return retVal;
}
int
syscall_read(int fd, void *buffer, unsigned size)
{
	int readBytes = 0;

	if(!check(buffer)) syscall_exit(-1);
	
	if(fd == 0)						//If we are in the same directory as the file
	{
		while(size > 0)
		{
			input_getc();
			size--;
			readBytes++;
		}
		return readBytes;
	}
	else
	{								//Otherwise grab the file from the directory and call the supplied file_read function
		if(findFile(fd) == NULL) return -1;
		
		lock_acquire(&sys_lock);
		readBytes = file_read(findFile(fd)->file, buffer, size);
		lock_release(&sys_lock);

		return readBytes;
	}
}
int
syscall_write(int fd, const void *buffer, unsigned size)
{
	int totalBytes = 0;
	char *buffChar = NULL;
	
	if (!check(buffer)) syscall_exit(-1);

	buffChar = (char *) buffer;
	if(fd == 1)							//If we are in the adjacent file directory as file
	{
		while(size > 200)
		{
			putbuf(buffChar, 200);	//Places the characters into the buffer argument;
			buffChar += 200;		//
			size -= 200;			//
			totalBytes += 200;		//Write files in increments of 200 bytes so problems don't arise
		}
		putbuf(buffChar, size);		//Places remaining characters into buffer
		totalBytes += size;
		return totalBytes;
	}
	else
	{										//Otherwise grab the file from the directory and call the supplied file_write function
		if(findFile(fd) == NULL) return 0;
		
		lock_acquire(&sys_lock);
		totalBytes = file_write(findFile(fd)->file, buffer, size);
		lock_release(&sys_lock);
		
		return totalBytes;
	}
}
void
syscall_seek(int fd, unsigned position)
{
	if(findFile(fd) == NULL) return;
	
	lock_acquire(&sys_lock);
	file_seek(findFile(fd)->file, position);
	lock_release(&sys_lock);
}
unsigned
syscall_tell(int fd)
{
	unsigned retVal;
	if(findFile(fd) == NULL) return 0;

	lock_acquire(&sys_lock);
	retVal = file_tell(findFile(fd)->file);
	lock_release(&sys_lock);
	return retVal;
}
void
syscall_close(int fd)
{
	if(findFile(fd) == NULL) return;
	
	lock_acquire(&sys_lock);
	file_close(findFile(fd)->file);
	lock_release(&sys_lock);
	list_remove(&findFile(fd)->elem);
}
