#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

bool less_fd(const struct list_elem *e1, const struct list_elem *e2, void *aux); 
int getSmallestFd(void);
struct fileDesc* find_file_by_fd(int fd);

static void syscall_handler (struct intr_frame *);
static int syswrite(int fd, const char *buf, unsigned length);
static int sysread(int fd, char *buf, unsigned length);
static int sysopen(const char *fname);
static void sysclose(int fd);

static struct lock mutex;
struct list fdList;
struct fileDesc {
  struct file *file;
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
  int ret = -1;
  void *esp = f->esp;
  uint32_t *argv = (f->esp+4);
  uint32_t number = *(uint32_t *)esp;
  struct thread *t = thread_current();
  switch(number){
    case SYS_CLOSE:
      sysclose((int)*argv);
      break;

    case SYS_OPEN:
      ret = sysopen((char*)*argv);
      break;

    case SYS_WRITE:
      ret = syswrite((int)*argv, (char*)*(argv+1), *(argv+2));
      break;

    case SYS_READ:
     ret = sysreaed((int)*argv, (char*)*(argv+1), *(argv+2));
     break;

    case SYS_EXIT:
      printf("%s: exit(0)\n",t->name);
      thread_exit();
      break;

    default:
      break;
  }

  f->eax = ret;
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
sysread(int fd, char *buf, unsigned length){
  int ret = -1;
  return ret;
}

int
sysopen(const char *fname){
  struct file *f;
  struct fileDesc *fDesc = (struct fileDesc*)malloc(sizeof(struct fileDesc));
  f = filesys_open(fname);
  if(!f){
    free(fDesc);
    return -1;
  }
  fDesc->file = f;
  fDesc->fd = getSmallestFd();
  list_insert_ordered(&fdList, &fDesc->elem, less_fd,NULL);
  return fDesc->fd;
}


static void
sysclose(int fd){
  struct fileDesc *f;
  f = find_file_by_fd(fd);
  if(f==NULL)
    return;
  file_close(f->file);
  list_remove(&f->elem);
  free(f);
}
  
//-------------------------------------------------------------------


int
getSmallestFd(){
  int fd = 2;
  struct list_elem *e;

  for(e = list_begin(&fdList); e != list_end(&fdList); e = list_next(e)){
    struct fileDesc *f = list_entry(e, struct fileDesc, elem);
    if( fd !=f->fd){
      break;
    }
    fd++;
  }
  return fd;
}

struct fileDesc *
find_file_by_fd(int fd){
  struct list_elem *e;
  struct fileDesc *f;
  for(e = list_begin(&fdList); e!= list_end(&fdList); e=list_next(e)){
    f = list_entry(e,struct fileDesc, elem);
    if(f->fd == fd)
      return f;
  }
  return NULL;
}

bool
less_fd(const struct list_elem *e1, const struct list_elem *e2, void *aux UNUSED){
  struct fileDesc *f1 = list_entry(e1, struct fileDesc, elem);
  struct fileDesc *f2 = list_entry(e2, struct fileDesc, elem);
  return f1->fd < f2->fd;
}
