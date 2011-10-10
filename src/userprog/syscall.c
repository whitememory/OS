#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
static struct lock mutex;

void
syscall_init (void) 
{
  lock_init(&mutex);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  lock_acquire(&mutex);
  void *esp = f->esp;
  uint32_t *argv = (f->esp+4);
  uint32_t number = *(uint32_t *)esp;
  switch(number){
    case SYS_OPEN:
       
    case SYS_WRITE:
      if((int)*argv == STDOUT_FILENO)
        putbuf((char *)(*(argv+1)), (*(argv+2)));
      f->eax = -1; 
      break;
    case SYS_EXIT:{
      struct thread *t = thread_current();
      printf("%s: exit(0)\n",t->name);
      thread_exit();
      break;
    }
    default:
      break;
  }

  lock_release(&mutex);
  
  return;  
}

