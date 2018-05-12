#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);
void syscall_halt (void);
int syscall_wait(pid_t aa);
void syscall_exit(int a);
bool syscall_remove(const char *name);
pid_t syscall_exec(const char* cmd_line);
int syscall_open(const char* file);
int syscall_filesize(int fd);
int syscall_read(int fd, void* buffer, unsigned size);
int syscall_write(int fd, const void* buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);
void check(const void *addr);

struct lock file_lock;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
 // printf ("system call!\n");
 // thread_exit (0);
 if(!(check(f->esp)))
 {
 		
 		quit();
 }
  switch(*(int*) f->esp);
  case SYS_HALT:
  	syscall_halt();
  	break;
  case SYS_WAIT:
  	pid_t pid;
  	pid = (*int*) f->esp+1;
  	f->eax = syscall_wait(pid);
  	break;
  case SYS_CREATE:
  	int *pointer = f->esp;
  	bool check1 = check(pointer+1);
  	bool check2 = check(*(pointer+1));
  	if(check1 || check2)
  	{
  		quit();
  	}
  	else
  	{
  		char *name = (const char *)*(unsigned int *)p+1;
  		unsigned int size = *((unsigned int *)p+2);
		create(name, size);
  	}
  	break;
  case SYS_REMOVE:
  	//check validity
  	syscall_remove(*(p+1));
  	break;
  case SYS_OPEN:		//const char* file
  	//check validity
  	syscall_open(*(p+1));
  	break;
}
void
check(const void addr*)
{
	if(!is_use_vaddr(addr)){
	
	}
	quit();
}
bool create (const char *file, unsigned initial_size){
	lock_acquire(&file_lock);
	bool status = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return status;
}
void 
quit()
{

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
	thread_exit(a);
}

bool
syscall_remove(const char *name)
{

//lock
	f->eax = filesys_remove(name);
	bool retVal = false;
	if(f->eax != NULL)
	{
		retVal = true;
	}
//release lock
	return retVal;	
}
int
syscall_open(const char *file)
{
	//acquire lock
	struct file *opened = filesys_open(file);
	if(!f){
	f->eax = -1;
	//release lock
	return -1;
	}
	//release lock
	int retVal = process_add_file(opened);
}
