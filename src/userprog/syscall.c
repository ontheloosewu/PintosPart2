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
static struct currFile* getFile (int);
//struct lock files;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
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
  	syscall_halt();
  	break;
  case SYS_EXIT:
	{
	syscall_exit(fd);
	break;
	}
  case SYS_EXEC:
	{
	*eax = (uint32_t) syscall_exec(argChar);
  	break;
	}
  case SYS_WAIT:
	{
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
	*eax = (uint32_t) syscall_create(argChar, argUS);
  	break;
	}
  case SYS_REMOVE:
	{
  	//check validity
  	//syscall_remove(*(f->esp+1), f);
	*eax = (uint32_t) syscall_remove(argChar);
  	break;
	}
  case SYS_OPEN:
	{
  	//check validity
  	//syscall_open(*(f->esp+1));
	*eax = (uint32_t) syscall_open(argChar);
  	break;
	}
  case SYS_FILESIZE:
	{
	*eax = (uint32_t) syscall_filesize(fd);
	break;
	}
  case SYS_READ:
	{
	*eax = (uint32_t) syscall_read(fd, argVoid, argUS3);
	break;
	}
  case SYS_WRITE:
	{
	*eax = (uint32_t) syscall_write(fd, argVoid, argUS3);
	break;
	}
  case SYS_SEEK:
	{
	syscall_seek(fd, argUS);
	break;
	}
  case SYS_TELL:
	{
	*eax = (uint32_t) syscall_tell(fd);
	break;
	}
  case SYS_CLOSE:
	{
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
	tid_t child_tid = TID_ERROR;

	if(!check(cmd_line)) syscall_exit(-1);

	child_tid = process_execute(cmd_line);
	return child_tid;
}
bool 
syscall_create(const char *file, unsigned initial_size)
{
	bool retVal = false;
	if(check(file))
	{
		lock_acquire(&filesys_lock);
		retVal = filesys_create(file, initial_size);
		lock_release(&filesys_lock);
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
		lock_acquire(&filesys_lock);
		retVal = filesys_remove(file);
		lock_release(&filesys_lock);
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
		opened->fd = thread_current()->next_fd;
		thread_current()->next_fd++;
		lock_acquire(&filesys_lock);
		opened->file = filesys_open(file);
		lock_release(&filesys_lock);
		
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
	if(getFile(fd) == NULL) return 0;
	lock_acquire(&filesys_lock);
	retVal = file_length(getFile(fd)->file);
	lock_release(&filesys_lock);
	return retVal;
}
int
syscall_read(int fd, void *buffer, unsigned size)
{
	int readBytes = 0;

	if(!check(buffer)) syscall_exit(-1);
	
	if(fd == 0)
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
	{
		if(getFile(fd) == NULL) return -1;
		
		lock_acquire(&filesys_lock);
		readBytes = file_read(getFile(fd)->file, buffer, size);
		lock_release(&filesys_lock);

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
	if(fd == 1)
	{
		while(size > 200)
		{
			putbuf(buffChar, 200);
			buffChar += 200;
			size -= 200;
			totalBytes += 200;
		}
		putbuf(buffChar, size);
		totalBytes += size;
		return totalBytes;
	}
	else
	{
		if(getFile(fd) == NULL) return 0;
		
		lock_acquire(&filesys_lock);
		totalBytes = file_write(getFile(fd)->file, buffer, size);
		lock_release(&filesys_lock);
		
		return totalBytes;
	}
}
void
syscall_seek(int fd, unsigned position)
{
	if(getFile(fd) == NULL) return;
	
	lock_acquire(&filesys_lock);
	file_seek(getFile(fd)->file, position);
	lock_release(&filesys_lock);
}
unsigned
syscall_tell(int fd)
{
	unsigned retVal;
	if(getFile(fd) == NULL) return 0;

	lock_acquire(&filesys_lock);
	retVal = file_tell(getFile(fd)->file);
	lock_release(&filesys_lock);
	return retVal;
}
void
syscall_close(int fd)
{
	if(getFile(fd) == NULL) return;
	
	lock_acquire(&filesys_lock);
	file_close(getFile(fd)->file);
	lock_release(&filesys_lock);
	list_remove(&getFile(fd)->elem);
}
static struct currFile *
getFile(int fd)
{
	struct thread *curr = thread_current();
	struct list_elem *elem;
	for(elem = list_begin(&curr->openfiles); elem != list_end(&curr->openfiles); elem = list_next(elem))
	{
		struct currFile *cF = list_entry (elem, struct currFile, elem);
		if(cF->fd == fd) return cF;
	}
	return NULL;
}
