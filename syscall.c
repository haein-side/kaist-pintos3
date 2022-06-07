#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* 추가해준 헤더 파일들 */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* syscall functions */
void halt (void);
void exit (int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
int _write (int fd UNUSED, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork (const char *thread_name);
int exec (const char *file_name);

/* syscall helper functions */
void check_address(const uint64_t*);
static struct file *process_get_file(int fd);
int process_add_file(struct file *file);
void process_close_file(int fd);

/* Project2-extra */
const int STDIN = 1;
const int STDOUT = 2;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry); // syscall-entry.S로 진입

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL.
	 * syscall_entry에 들어가서 userland stack에 있는 걸 kernel mode stack으로 다 옮길 때까지 
	 * 어떤 인터럽트도 serve해주면 안 됨 -> FLAG_FL이라고 설정해둠 */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	/* LOCK INIT 추가*/
	lock_init(&filesys_lock); // filesys_lock의 semaphore를 1로 초기화 (풀려있는 상태)
}

/* helper functions letsgo ! */
void check_address(const uint64_t* addr){
	struct thread *t = thread_current(); 
	/* 포인터가 가리키는 주소가 유저영역의 주소인지 확인 (시스템 콜은 유저영역에서!) */
	/* what if the user provides an invalid pointer, a pointer to kernel memory, 
	 * or a block partially in one of those regions */
	/* 잘못된 접근인 경우, 프로세스 종료 */
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4, addr) == NULL)
		exit(-1);
} 

int process_add_file(struct file *f){
	struct thread *curr = thread_current();
	struct file **curr_fd_table = curr->file_descriptor_table;
	for (int idx = curr->fdidx; idx < FDCOUNT_LIMIT; idx++){
		if(curr_fd_table[idx] == NULL){
			curr_fd_table[idx] = f;
			curr->fdidx = idx; // fd의 최대값 + 1 // 논란있을듯???
			return curr->fdidx;
		}
	}
	curr->fdidx = FDCOUNT_LIMIT; // 이게 1 FAIL 의 원인
	return -1;
}

struct file *process_get_file (int fd){
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;
	struct file *f = thread_current()->file_descriptor_table[fd];
	return f;
}

/* revove the file(corresponding to fd) from the FDT of current process */
void process_close_file(int fd){
	if (fd < 0 || fd > FDCOUNT_LIMIT)
		return NULL;
	thread_current()->file_descriptor_table[fd] = NULL;
}

void remove_file_from_fdt (int fd) {
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}
	cur->file_descriptor_table[fd] = NULL;
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	int syscall_num = f->R.rax; // rax: system call number (user syscall에서 넘겨줌)
	switch(syscall_num){
		case SYS_HALT:                   /* Halt the operating system. */
			halt();
			break;
		case SYS_EXIT:                   /* Terminate this process. */
			exit(f->R.rdi);
			break;    
		case SYS_FORK:   ;                /* Clone current process. */
			struct thread *curr = thread_current(); //부모
			memcpy(&curr->parent_if, f, sizeof(struct intr_frame));
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:                   /* Switch current process. */
			if (exec(f->R.rdi) == -1)
				exit(-1);
			break;
		case SYS_WAIT:                   /* Wait for a child process to die. */
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:                 /* Create a file. */
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:                 /* Delete a file. */
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:                   /* Open a file. */
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:               /* Obtain a file's size. */
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:                   /* Read from a file. */
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:                  /* Write to a file. */
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:                   /* Change position in a file. */
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:                   /* Report current position in a file. */
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:					 /* Close a file. */
			close(f->R.rdi);
			break;
		case SYS_DUP2:
			f->R.rax = dup2(f->R.rdi, f->R.rsi);
			break;
		default:						 /* call thread_exit() ? */
			exit(-1);
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

//변경사항 

/* halt the operating system */
/* 핀토스를 종료 */ 
void halt(void){
	power_off(); // init.c의 power_off 활용
}

/* terminate this process */
/* 현재 돌고 있는 프로세스만 종료 */
void exit(int status){
	struct thread *curr = thread_current(); // 실행 중인 스레드 구조체 가져오기
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status); // if status != 0 (error: 정상적으로 종료됐다면 status는 0)
	thread_exit(); // 스레드 종료
}

/* Clone current process. */
tid_t fork (const char *thread_name){
	/* create new process, which is the clone of current process with the name THREAD_NAME*/
	struct thread *curr = thread_current();
	return process_fork(thread_name, &curr->parent_if);
	/* must return pid of the child process */
}

int exec (const char *file){
	// printf("file 이름 %s\n", file); child-simple

	check_address(file);
	int size = strlen(file) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO); // 하나의 커널 가용 페이지를 할당하고 그 커널 페이지의 가상 주소를 리턴
	
	if(fn_copy==NULL)
		exit(-1);
	
	strlcpy(fn_copy, file, size);
	// 문자열을 복사해주는 함수
	// fn_copy 안에 file의 값을 '\0'값을 만나기 전 or size-1만큼 복사가 이뤄졌을 때 복사 중지
	// fn_copy 에 file의 값 복사
	if (process_exec(fn_copy) == -1)
		return -1;

	NOT_REACHED();
	return 0;
}

/* Wait for a child process to die. */
int wait(tid_t pid){
	process_wait(pid);
}

/* Create a file. */
/* 파일 생성하는 시스템 콜 */
bool create(const char *file, unsigned initial_size){ // 문자열은 그 자체로 주소임 그래서 * 포인터 변수로 받는 것!
	check_address(file); // 포인터가 가리키는 주소가 유저영역의 주소인지 확인 (요청 보낸 영역이 유저영역인지 확인)
	return filesys_create(file, initial_size); // 파일 이름 & 크기에 해당하는 파일 생성
	// 디렉토리에 인자로 받은 name과 initial_size에 해당하는 inode_sector를 만들어줌 => file 생성된 것!
}

 /* Delete a file. */
bool remove(const char *file){
	check_address(file); // 포인터가 가리키는 주소가 유저영역의 주소인지 확인
	return filesys_remove(file); // 파일 이름에 해당하는 파일을 제거
}

/* 파일에 접근해서 여는 함수 
   반환하는 값은 fd (파일 디스크립터 번호)
*/
int open (const char *file) { // 해당 파일을 가리키는 포인터를 인자로 받음
	check_address(file); // 먼저 주소가 유효한지 체크
	lock_acquire(&filesys_lock);
	struct file *file_obj = filesys_open(file); // 열려고 하는 실제 물리주소와 연결된 파일 객체 정보 file_open (inode)를 filesys_open()으로 받기

	// 제대로 파일 "생성"됐는지 체크
	// 왜 open인데 생성??
	// file을 open한다는 건 새로운 파일 구조체 file을 만들고 거기에 접근하고 싶은 파일의 정보인 inode를 대입한 것을 반환해주는 것
	// file_open (inode)가 filesys_open(file)의 반환값으로 file_obj에 담김
	if (file_obj == NULL) {
		return -1; 
	}

	int fd = add_file_to_fd_table(file_obj); // 만들어진 파일을 스레드 내 fdt 테이블에 추가 -> 스레드가 해당 파일 관리 가능케

	// 만약 파일을 열 수 없으면 -1을 받음
	if (fd == -1) {
		file_close(file_obj);
	}
	lock_release(&filesys_lock);
	return fd;
}

int filesize (int fd){
	struct file *f = process_get_file(fd); // fd를 이용해서 파일 객체 검색
	if (f == NULL) return -1;
	return file_length(f);
}

// int read (int fd, void *buffer, unsigned size){
//    check_address(buffer);
//    unsigned char *buf = buffer;
//    int readsize;

//    struct file *f = process_get_file(fd);

//    if (f == NULL) return -1;
//    if (fd < 0 || fd>= FDCOUNT_LIMIT) return NULL;
//    if (f == STDOUT) return -1;
   
//    if (f == STDIN){
//       for (readsize = 0; readsize < size; readsize++){
//          char c = input_getc();
//          *buf++ = c;
//          if (c == '\0')
//             break;
//       }
//    }
//    else{
//       lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
//       readsize = file_read(f, buffer, size);
//       lock_release(&filesys_lock);
//    }
//    return readsize;
// }

int read (int fd, void *buffer, unsigned size){
	check_address(buffer);
	unsigned char *buf = buffer;
	int readsize;
	struct file *f = process_get_file(fd);
	struct thread *cur = thread_current();

	// Modified read func for dup2
	if (f == NULL) {
		return -1;
	}
	
	if (f == STDIN) {
		// for (readsize = 0; readsize < size; readsize++){
		// 	char c = input_getc();
		// 	*buf++ = c;
		// 	if (c == '\0')
		// 		break;
		// }
		if (cur->stdin_count == 0){ // stdin_count가 비정상적인 경우
			NOT_REACHED();
			process_close_file(fd);
			readsize = -1;
		}
		else {
			int i;
			unsigned char *buf = buffer;
			for (i = 0; i < size; i++){
				char c = input_getc();
				*buf++ = c;
				if (c == '\0'){
					break;
				}
			}
			readsize = i;
		}
	}
	else if (f == STDOUT) { // read에서 입출력 fd일 경우 -1 리턴
		readsize = -1;
	}
	else{
		lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
		readsize = file_read(f, buffer, size);
		lock_release(&filesys_lock);
	}
	return readsize;

}

/* 파일 디스크립터 번호가 가리키는 파일에 buffer의 값을 size만큼 write해줌
   writesize 반환 */ 
// int write (int fd, const void *buffer, unsigned size){ // length->size로 수정 (맞춰수정?)
// 	check_address(buffer);
// 	struct file *f = process_get_file(fd);
// 	int writesize;

// 	if (f == NULL) return -1;
// 	if (f == STDIN) return -1;

// 	if (f == STDOUT){ // 콘솔(모니터)로 write 해줄 때
// 		putbuf(buffer, size);// buffer에 들은 size만큼을, 한 번의 호출로 작성해준다.
// 		writesize = size;
// 	}
// 	else{ // 콘솔이 아니라 특정 파일에 write를 해줄 때 (ex. 파일을 닫을 때 하드에 있는 파일의 값을 바꿔줘야)
// 		lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
// 		writesize = file_write(f, buffer, size);
// 		lock_release(&filesys_lock);
// 	}
// 	return writesize;
// }

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int write_result;
	struct file *file_fd = process_get_file(fd);

	if (file_fd == NULL) {
		return -1;
	}

	struct thread *cur = thread_current();

	if (file_fd == STDOUT) {
		if (cur->stdout_count == 0){
			NOT_REACHED();
			remove_file_from_fdt(fd);
			write_result = -1;
		}
		else {
			putbuf(buffer, size);
			write_result = size;
		}
	}
	else if (file_fd == STDIN) {
		write_result = -1;
	}
	else {
		lock_acquire(&filesys_lock); // 파일에 동시접근 일어날 수 있으므로 lock 사용
		write_result = file_write(file_fd, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_result;
}


void seek (int fd, unsigned position){
	struct file *f = process_get_file(fd);
	if (f > 2)
		file_seek(f, position);
}

unsigned tell (int fd){
	struct file *f = process_get_file(fd);
	if (fd < 2)
		return;
	return file_tell(f);
}

// void close (int fd){
// 	if(fd < 2) return;
// 	struct file *f = process_get_file(fd);

// 	if(f == NULL)
// 		return;
// 	/* 여긴 그냥 fd < 2로도 가능할듯 */
// 	process_close_file(fd);
// 	file_close(f);
// }

void close(int fd)  {
	struct file *close_file = process_get_file(fd);

	if (close_file == NULL) {
		return;
	}

	struct thread *cur = thread_current();

	if (fd == 0 || close_file == STDIN) {
		cur -> stdin_count--;
	}
	else if (fd == 1 || close_file == STDOUT) {

		cur -> stdout_count--;
	}

	remove_file_from_fdt(fd);

	if (fd <= 1 || close_file <= 2){
		return;
	}

	if (close_file -> dup_count == 0){
		file_close(close_file);
	}
	else {
		close_file->dup_count--;
	}

}

/* 기존의 파일 디스크립터 oldfd를 새로운 newfd로 복제하여 생성 */
int dup2(int oldfd, int newfd) {
	struct file *file_fd = process_get_file(oldfd);

	if (file_fd == NULL) {
		return -1;
	} 

	if (oldfd == newfd) {
		return newfd;	// oldfd == newfd이면 복제하지 않고 newfd 리턴
	}

	struct thread *cur = thread_current();
	struct file **fdt = cur->file_descriptor_table;

	if (file_fd == STDIN){
		cur->stdin_count++;
	}
	else if (file_fd == STDOUT){
		cur->stdout_count++;
	}
	else {
		file_fd->dup_count++;
	}

	close(newfd);
	fdt[newfd] = file_fd;
	return newfd;
 
}