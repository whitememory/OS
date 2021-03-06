#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "devices/input.h"

bool less_fd(const struct list_elem *e1, const struct list_elem *e2, void *aux); 
int getSmallestFd(void);
struct fileDesc* find_file_by_fd(int fd);

static void syscall_handler (struct intr_frame *);
static int syswrite(int fd, const char *buf, unsigned length);
static int sysread(int fd, char *buf, unsigned length);
static int sysopen(const char *fname);
static bool syscreate(const char *file, unsigned size);
static void sysclose(int fd);
static void sysexit(int status);

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
  struct thread *t = thread_current();
  lock_acquire(&mutex);
  int ret = -1;
  void *esp = f->esp;
  uint32_t *argv = (f->esp+4);
  if(pagedir_get_page(t->pagedir, esp)==NULL || pagedir_get_page(t->pagedir,esp+12 )==NULL)
    sysexit(-1);
  uint32_t number = *(uint32_t *)esp;
  
  switch(number){
    case SYS_HALT:
      break;

    case SYS_EXEC:
      break;

    case SYS_WAIT:
      break;

    case SYS_REMOVE:
      break;

    case SYS_FILESIZE:
      break;

    case SYS_SEEK:
      break;

    case SYS_TELL:
      break;

    case SYS_CREATE:
      ret = syscreate((char *)*argv, (int)*(argv+1));
      break;

    case SYS_CLOSE:
      sysclose((int)*argv);
      break;

    case SYS_OPEN:
      ret = sysopen((char*)*argv);
      break;

    case SYS_WRITE:
      ret = syswrite((int)*argv, (char*)*(argv+1), (unsigned)*(argv+2));
      break;

    case SYS_READ:
     ret = sysread((int)*argv, (char*)*(argv+1), (unsigned)*(argv+2));
     break;

    case SYS_EXIT:
      sysexit((int)*argv);
      break;

    default:
      sysexit(-1);
      break;
  }

  f->eax = ret;
  lock_release(&mutex);
  return;  
}

static void
sysexit(int status){
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

static int
syswrite(int fd, const char *buf, unsigned length){
  int ret = -1;
  if(pagedir_get_page(thread_current()->pagedir,buf)==NULL || pagedir_get_page(thread_current()->pagedir,buf+length)==NULL)
    sysexit(-1);
  //if(buf==NULL)
  //  sysexit(-1);

  if(fd==STDOUT_FILENO)
    putbuf(buf, length);
  else if(fd==STDIN_FILENO)
    return ret;
  else{
    struct fileDesc *f = find_file_by_fd(fd);
    if(f==NULL)
      return -1;
    ret = file_write(f->file, buf, length);
  }
  return ret;
}

static int
sysread(int fd, char *buf, unsigned length){
  int ret = -1;
  if(!is_user_vaddr(buf+length) )
    sysexit(-1);
  if(buf==NULL)
    sysexit(-1);

  if(fd==STDOUT_FILENO)
    return -1;
  else if(fd==STDIN_FILENO){
    unsigned i;
    for(i=0; i<length; i++){
      buf[i] = input_getc();
    }
    buf[length] = (char)NULL;
  }
  else{
    struct fileDesc *f = find_file_by_fd(fd);
    if(f==NULL)
      return -1;
    ret = file_read(f->file, buf, length);
  }
    
  return ret;
}

int
sysopen(const char *fname){
  struct file *f;
  struct fileDesc *fDesc = (struct fileDesc*)malloc(sizeof(struct fileDesc));
  if(fname ==NULL)
    sysexit(-1);
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

static bool 
syscreate(const char *file, unsigned size){
  if(file==NULL)
    sysexit(-1);
  if(!file)
    return false;
  struct inode *inode = NULL;
  struct dir *dir = dir_open_root();
  if(dir != NULL){
    if(dir_lookup(dir_open_root(),file, &inode)){
      inode_close(inode);
      return false;
    }
  }
  return filesys_create(file, size);
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
