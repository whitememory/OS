#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"

bool less_fd(const struct list_elem *e1, const struct list_elem *e2, void *aux); 
static void syscall_handler (struct intr_frame *);
static int syswrite(int fd, const char *buf, unsigned length);
static int sysopen(const char *fname);

static struct lock mutex;
struct list fdList;
struct fileDesc {
  struct file *f;
  int fd;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  list_init(&fdList);
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
      sysopen((char*)*argv);
    case SYS_WRITE:
      syswrite((int)*argv, (char*)*(argv+1), *(argv+2));
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

static int
syswrite(int fd, const char *buf, unsigned length){
  int ret = -1;
  if(fd==STDOUT_FILENO)
    putbuf(buf, length);
  return ret;
}

static int
sysopen(const char *fname){
  struct file *f;
  struct fileDesc *fDesc = (struct fileDesc*)malloc(sizeof(struct fileDesc));
  f = filesys_open(fname);
  if(f==NULL){
    free(fDesc);
    return -1;
  }
  fDesc->file = f;
  fDesc->fd = k;
}

int
getSmallestFd(){
  
  return -1;
}




bool
less_fd(const struct list_elem *e1, const struct list_elem *e2, void *aux){
  struct fileDesc *f1 = list_entry(e1, struct fileDesc, elem);
  struct fileDesc *f2 = list_entry(e2, struct fileDesc, elem);
  return f1->fd < f2->fd;
}
