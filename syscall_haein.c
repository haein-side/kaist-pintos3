// #include "userprog/syscall.h"
// #include <stdio.h>
// #include <syscall-nr.h>
// #include "threads/interrupt.h"
// #include "threads/thread.h"
// #include "threads/loader.h"

// #include "threads/flags.h"
// #include "threads/synch.h"
// #include "threads/init.h"
// #include "filesys/filesys.h"
// #include "filesys/file.h"
// #include "userprog/gdt.h"
// #include "intrinsic.h"
// #include "threads/palloc.h"

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

#define MAX_FD_NUM	(1<<9) 

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void syscall_init (void);

void check_address(void *addr); 
struct file *fd_to_struct_filep (int fd);
int add_file_to_fd_table (struct file *file);
void remove_file_from_fdt (int fd);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned intial_size);
bool remove (const char *file);
int write (int fd, const void *buffer, unsigned size);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
tid_t fork (const char *thread_name, struct intr_frame *f);

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

// struct lock filesys_lock;

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
		
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {// f: 시스템콜을 호출한 유저 프로그램(caller)에 대한 정보를 저장해둔 구조체
	/* 유저 스택에 저장되어 있는 시스템 콜 넘버를 가져오기 */
	uintptr_t *rsp = f->rsp;
	check_address((void *) rsp);
	int sys_number = f-> R.rax; // rax: 레지스터에 시스템 콜 넘버가 저장되어 있음

	/* 인자 들어오는 순서 
		1번째 인자: %rdi
		2번째 인자: %rsi
		3번째 인자: %rdx
		번째 인자: %r10
		5번째 인자: %r8
		6번째 인자: %r9 	
	*/
	// printf("시스템콜 넘버 %d\n", sys_number);
	// TODO: Your implementation goes here.
	switch(sys_number) { // 인터럽트 프레임에 저장되어 있던 시스템 콜 넘버: 어떤 시스템 콜 함수를 호출하는지 저장해둔 넘버
		case SYS_HALT: 		// 0
			halt();
			break;
		case SYS_EXIT: 		// 1
			exit(f->R.rdi);
			break;
		case SYS_FORK:  	// 2
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi)== -1) // exec 함수는 성공 시 리턴값 없음
				exit(-1); 			// 실패 시 프로세스는 exit(-1)과 함께 종료됨 (프로그램이 load 혹은 run 못했을 경우)
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rdx);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:		   // default: case문들 중 어느 것도 해당되지 않을 때 실행됨
			thread_exit(); // 시스템콜 함수 진행 중인 커널 스레드를 종료시킴

	}

	// printf ("system call!\n");
	// printf("exit 위!\n");
	// thread_exit ();
}

/* 주소값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수
   (유저가상메모리 주소인지 아닌지)
   유저가상메모리 영역을 벗어났을 경우 프로세스 종료 (exit(-1)) */
void
check_address(void *addr) {
	struct thread *curr = thread_current ();
	// 짰던 코드 
	// 이렇게 짜면 안되는 이유: addr은 VA이기 때문에 PA인 USER_STACK과 LOADER_KERN_BASE와 비교하면 안 됨
	// if ((addr >= LOADER_KERN_BASE && addr < USER_STACK) || pml4_get_page(curr->pml4, addr) == NULL) { 
	// 	// 인자로 받은 주소값이 KERN_BASE보다 높은 값의 주소값을 가진 경우 or 매핑되지 않은 주소인 경우
	// 	fail ("invalid address");
	// }
	
	// 이렇게 하면 되려나? 나중에 테스트 해보기
	// if ((vtop(addr) >= LOADER_KERN_BASE && vtop(addr) < USER_STACK) || pml4_get_page(curr->pml4, addr) == NULL) { 
	// 	// 인자로 받은 주소값이 KERN_BASE보다 높은 값의 주소값을 가진 경우 or 매핑되지 않은 주소인 경우
	// 	fail ("invalid address");
	// }

	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL) { 
		// 인자로 받은 주소값이 KERN_BASE보다 높은 값의 주소값을 가진 경우 or 매핑되지 않은 주소인 경우
		// 현재 프로세스를 종료시킴
		exit(-1);
		
	}

}

/* pintos 전체를 종료시키는 시스템 콜 */
void halt (void) {
	power_off(); /* Poweroff command for qemu(핀토스 테스트 돌려주는 에뮬레이터) */
}

/* 현재 프로세스를 종료시키는 시스템 콜 */
void exit (int status) {
	struct thread *t = thread_current();
	t->exit_status = status;
	// printf("들어오나\n");
	printf("%s: exit(%d)\n", t->name, status); // Process Termination Mesage
	/* 정상적으로 종료됐다면 status는 0 */
	/* status: 프로그램이 정상적으로 종료됐는지 확인 */
	thread_exit(); // 핀토스는 프로세스가 곧 스레드 (1:1 매핑), USERPROG로 들어감 (요청자)
}

/* 파일을 새로 생성하는 시스템 콜 */
bool create (const char *file, unsigned intial_size) { // file: 생성할 파일의 이름 및 경로 정보, initial_size: 생성할 파일의 크기
	/* 성공이면 true, 실패면 false */
	check_address(file); // 파일의 VA가 VM 영역을 벗어났을 경우 현재 프로세스 종료해줌

	if (filesys_create(file, intial_size)) {
		return true;
	} else {
		return false;
	}
}

/* 파일을 제거하는 시스템 콜 */
bool remove (const char *file) {
	check_address(file);

	if (filesys_remove(file)) { // 이때, 파일을 제거하더라도 그 이전에 파일을 오픈했다면 
								// 해당 오픈 파일은 close되지 않고 그대로 켜진 상태로 남아있는다.
		return true;
	} else {
		return false;
	}
}

/* 열린 파일의 데이터를 기록하는 시스템 콜 */
int write (int fd, const void *buffer, unsigned size) {
	// check_address(buffer);
	// struct file *fileobj = fd_to_struct_filep(fd);
	// int read_count;

	// lock_acquire(&filesys_lock);

	// if (fd == STDOUT_FILENO) { // 파일 디스크립터 번호가 1인(출력을 하라는) 경우에 한해 값을 출력하는 함수를 작성
	// 	putbuf(buffer, size); // 버퍼에 들어있는 값을 size만큼 출력
	// 	read_count = size;
	// }	
	
	// else if (fd == STDIN_FILENO) {
	// 	lock_release(&filesys_lock);
	// 	return -1;
	// }

	// else if (fd >= 2) {
	// 	if (fileobj == NULL){
	// 		lock_release(&filesys_lock);
	// 		exit(-1);
	// 	}
	// 	read_count = file_write(fileobj, buffer, size);
	// }
	// lock_release(&filesys_lock);
	// return read_count;
	// // else {
		
	// // 	lock_acquire(&filesys_lock);
	// // 	read_count = file_write(fileobj, buffer, size);
	// // 	lock_release(&filesys_lock);

	// // }

	check_address(buffer);
	int ret;

	struct file *fileobj = fd_to_struct_filep(fd);
	if (fileobj == NULL)
		return -1;

	struct thread *curr = thread_current();
	
	if (fileobj == STDOUT)
	{
		if(curr->stdout_count == 0)
		{
			//Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			/* 버퍼를 콘솔에 출력 */
			putbuf(buffer, size);
			ret = size;
		}
	}
	else if (fileobj == STDIN)
	{
		ret = -1;
	}
	else
	{
		lock_acquire(&filesys_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}

	return ret;

}

/* 파일에 접근해서 여는 함수 */
int open (const char *file) { // 해당 파일을 가리키는 포인터를 인자로 받음
	check_address(file); // 먼저 주소가 유효한지 체크
	lock_acquire(&filesys_lock);
	struct file *file_obj = filesys_open(file); 
	// file 주소값이 dir의 inode를 가리키는 포인터를 가지고 있음
	// 열려고 하는 물리주소와 연결된 파일 객체 정보 file_open (inode)를 filesys_open()으로 받기

	// file_open (inode)가 filesys_open(file)의 반환값으로 file_obj에 담김
	if (file_obj == NULL) {
		return -1; 
	}

	int fd = add_file_to_fd_table(file_obj); // 메모리에서 열어준 파일을 스레드 내 fdt 테이블에 추가 -> 스레드가 해당 파일 관리 가능케

	// 만약 파일을 열 수 없으면 -1을 받음
	if (fd == -1) {
		file_close(file_obj);
	}
	lock_release(&filesys_lock);
	return fd;
}

 /* 파일을 현재 프로세스의 fdt에 추가 */
int add_file_to_fd_table (struct file *file) { // file 구조체에 inode 관련 정보를 멤버로 넣어둔 걸 인자로 받음
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx; // fd 값은 2부터 출발 (0은 stdin - 표준입력, 1은 stdout -표준출력)
						// fd 는 파일 디스크립터로, FDT에서 해당 파일의 인덱스 번호
	while (t->file_descriptor_table[fd] != NULL && fd < FDCOUNT_LIMIT) {
		fd++;
	}

	if (fd >= FDCOUNT_LIMIT) {
		return -1;
	}
	t->fdidx = fd;
	fdt[fd] = file;
	return fd;
}

/* fd 값을 넣으면 해당 file을 반환하는 함수 */
// 예외 케이스 고려하여 fd 값이 0보다 작거나
// 파일 디스크립터 배열에 할당된 범위를 넘어서면 파일이 없다는 뜻이니 NULL을 반환 
// filesize()를 위한 함수
struct file *fd_to_struct_filep (int fd) {
	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return NULL;
	}

	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;

	struct file *file = fdt[fd];
	return file;
}

/* 열려 있는 파일을 FDT에서 찾아 해당 파일의 크기를 반환하는 함수 */
int filesize (int fd) {
	struct file *fileobj = fd_to_struct_filep(fd); /* fd 값을 넣으면 해당 file 객체를 반환하는 함수 */

	/* 추가 */	
	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}

	if (fileobj == NULL) {
		return -1;
	}
	file_length(fileobj);
}

/* 열린 파일의 데이터를 읽는 시스템 콜 */
// 성공 시 읽은 바이트 수를 반환, 실패 시 -1 반환
// buffer: 읽은 데이터를 저장할 버퍼 주소 값, size: 읽을 데이터 크기
// fd 값이 0일 때 키보드의 데이터를 읽어 버퍼에 저장 (input_getc() 이용)
int read (int fd, void *buffer, unsigned size) {
	// 유효한 주소인지부터 체크
	check_address(buffer); // 버퍼 시작 주소 체크
	check_address(buffer + size - 1); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	int read_count;

	struct file *fileobj = fd_to_struct_filep(fd); /* fd 값을 넣으면 해당 file 객체를 반환하는 함수 */

	/* 추가 */
	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}

	if (fileobj == NULL) { // 파일 읽어오는 것 실패 시 -1 반환
		return -1;
	}

	/* STDIN일 때 */
	if (fd == STDIN_FILENO) { // 표준 입력: fd 값이 0일 때
		char key;
		for (int read_count = 0; read_count < size; read_count++) {
			key = input_gㅔㄴetc();
			*buf++ = key;
			if (key == '\0') { // 엔터값
				break;
			}
		}
	}

	/* STDOUT일 때: -1 반환 */ 
	else if (fd == STDOUT_FILENO) { // 표준 출력: fd 값이 1일 때
		return -1;
	} 
	
	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size); // 파일 읽어들일 동안에만 lock을 걸어줌
		lock_release(&filesys_lock);
	}

	return read_count;
}


/* 열려있는 파일 fd에 쓰거나 읽을 바이트의 위치(position)를 파일 객체의 pos에 변경하는 시스템콜 */
/*   파일을 읽거나 쓸 때 기본 세팅은 항상 파일의 시작 위치로 되어 있음
   따라서 우리가 입력해줄 position 위치부터 쓰거나 읽을 수 있도록 해당 position을 찾는 함수
   이를 위해 "파일 객체 내 멤버"인 pos를 인자 값인 position으로 변경해줌
*/
void seek (int fd, unsigned position) {
	if (fd < 2) {
		return;
	}
	struct file *file = fd_to_struct_filep(fd); // fd 값을 넣으면 해당 file을 반환하는 함수
	
	check_address(file); 
	
	if (file == NULL)  {
		return;
	}

	file_seek(file, position); // file 구조체 멤버인 pos(current position)의 값을 position으로 변경
}

/* fd 값을 인자로 넣어주면 해당 파일의 pos(current_position)를 반환하는 시스템 콜 */
unsigned tell (int fd) {
	if (fd < 2) { // 0 : STDIN, 1 : STDOUT
		return;
	}
	struct file *file = fd_to_struct_filep(fd);
	check_address(file);
	if (file == NULL) {
		return;
	}
	return file_tell(fd);
}

/* 열려있는 파일을 FDT에서 찾아 해당 파일을 닫아주는 시스템 콜 */
void close (int fd) {
	struct file *file = fd_to_struct_filep(fd);
	if (file == NULL) {
		return;
	}

	struct thread *cur = thread_current();

	// check_address(file);

	if (fd == 0 || file == STDIN) {
		cur->stdin_count--;
	} else if (fd == 1 || file == STDOUT) {
		cur->stdout_count--;
	}

	remove_file_from_fdt (fd);

	if (fd <= 1 || file <= 2) {
		return;
	}

	// if (fd->dupCount == 0) {
	// 	file_close(file);
	// } else {
	// 	file->dupCount--;
	// }

	// return file_close(fd);
}

void remove_file_from_fdt (int fd) {
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {
		return;
	}
	cur->file_descriptor_table[fd] = NULL;
}

/* 
부모 복사해서 자식 프로세스 생성하는 함수.
부모: 성공시 자식 pid 반환 / 실패 시 -1
자식: 성공시 0 반환
 */
tid_t fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

/* 현재 프로세스를 명령어로 입력 받은 실행파일로 변경하는 역할 */
int exec (char *file_name)
{
	check_address(file_name);
	int size = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO); // fn_copy로 복사하는 이유는 caller 함수와 load사이의 race condition을 방지하기 위함.
	if (fn_copy == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, file_name, size);

	if (process_exec(fn_copy) == -1) 	// 해당 프로세스를 메모리에 load하고 정소를 스택에 쌓는다.
		return -1;	// 오류 발생할 경우 -1 리턴

	NOT_REACHED();
	return 0;
}

int wait(tid_t pid) {
	process_wait(pid);
}