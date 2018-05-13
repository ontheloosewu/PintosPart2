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
  switch(*(int*) f->esp){
  case 0:
  	syscall_halt();
  	break;
  case 1:
	{
	int currStatus = *(((int *) esp) + 1);
	syscall_exit(currStatus);
	break;
	}
  case 2:
	{
  	const char *line = *(((char **) esp) + 1);
	*eax = (uint32_t) syscall_exec(line);
  	break;
	}
  case 3:
	{
	pid_t pid = *(((pid_t *) esp) + 1);
	*eax = (uint32_t) syscall_wait(pid);
	break;
	}
  case 4:
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
	const char *file = *(((char **) esp) + 1);
	unsigned initial_size = *(((unsigned *) esp) + 2);
	*eax = (uint32_t) syscall_create(file, initial_size);
  	break;
	}
  case 5:
	{
  	//check validity
  	//syscall_remove(*(f->esp+1), f);
	const char *file = *(((char **) esp) + 1);
	*eax = (uint32_t) syscall_remove(file);
  	break;
	}
  case 6:
	{
  	//check validity
  	//syscall_open(*(f->esp+1));
	const char *file = *(((char **) esp) + 1);
	*eax = (uint32_t) syscall_open(file);
  	break;
	}
  case 7:
	{
	int fd = *(((int *) esp) + 1);
	*eax = (uint32_t) syscall_filesize(fd);
	break;
	}
  case 8:
	{
	int fd = *(((int *) esp) + 1);
	void *buffer = (void *) *(((int **) esp) + 2);
	unsigned size = *(((unsigned *) esp) + 3);
	*eax = (uint32_t) syscall_read(fd, buffer, size);
	break;
	}
  case 9:
	{
	int fd = *(((int *) esp) + 1);
	const void *buffer = (void *) *(((int **) esp) + 2);
	unsigned size = *(((unsigned *) esp) + 3);
	*eax = (uint32_t) syscall_write(fd, buffer, size);
	break;
	}
  case 10:
	{
	int fd = *(((int *) esp) + 1);
	unsigned position = *(((unsigned *) esp) + 2);
	syscall_seek(fd, position);
	break;
	}
  case 11:
	{
	int fd = *(((int *) esp) + 1);
	*eax = (uint32_t) syscall_tell(fd);
	break;
	}
  case 12:
	{
	int fd = *(((int *) esp) + 1);
	syscall_close(fd);
	break;
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
	struct thread *curr = thread_current();
	curr->exitStatus = a;
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
	bool retVal;
	if(check(file))
	{
		lock_acquire(&filesys_lock);
		retVal = filesys_create(file, initial_size);
		lock_release(&filesys_lock);
		return retVal;
	}
	else
	{
		syscall_exit(-1);
	}
	return false;
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
	bool retVal;
	if(check(file))
	{
		lock_acquire(&filesys_lock);
		retVal = filesys_remove(file);
		lock_release(&filesys_lock);
		return retVal;
	}
	else syscall_exit(-1);

	return false;
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
	struct currFile *cF = NULL;
	cF = getFile(fd);
	if(cF == NULL) return 0;
	lock_acquire(&filesys_lock);
	retVal = file_length(cF->file);
	lock_release(&filesys_lock);
	return retVal;
}

struct 
currFile *getFile(int fd)
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
