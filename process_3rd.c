#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "userprog/process.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
struct thread *get_child(int pid);
void argument_stack(char **argv, int argc, struct intr_frame *if_);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	char *save_ptr;
	strtok_r(file_name," ",&save_ptr);
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *cur = thread_current();

	/* 전달받은 intr_frame을 현재 parent_if에 복사 */
	memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

	/* __do_fork를 실행하는 스레드 생성, 현재 스레드를 인자로 넘겨줌 */
	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, cur);
	if (tid == TID_ERROR)
		return TID_ERROR;

	struct thread *child = get_child(tid);
	sema_down(&child->fork_sema); // wait until child loads
	if (child->exit_status == -1)
		return TID_ERROR;

	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va))
	{
		return true;
	} 
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	// parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL)
	{
		// printf("[fork-duplicate] failed to fetch page for user vaddr 'va'\n"); // #ifdef DEBUG
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */

	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
	{
		// printf("[fork-duplicate] failed to palloc new page\n"); // #ifdef DEBUG
		return false;
	}


	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage,parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

struct MapElem
{
	/* key - parent's struct file */
	uintptr_t key;
	/* value - child's newly created struct file */
	uintptr_t value;
};

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	
	/* process_fork에서 전달받은 스레드 */
	struct thread *parent = (struct thread *) aux;
	/* process_fork에서 생성한 스레드 */
	struct thread *current = thread_current ();

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;
	
	/* process_fork에서 복사 해두었던 intr_frame */
	parent_if = &parent->parent_if;
	
	/* 1. Read the cpu context to local stack. */
	
	/* 부모의 intr_frame을 if_에 복사 */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	/* if_의 리턴값을 0으로 설정? */
	if_.R.rax = 0 ;

	/* 2. Duplicate Page table */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (parent->fdidx == FDCOUNT_LIMIT)
		goto error;

	/* Project2-extra) multiple fds sharing same file - use associative map 
	(e.g. dict, hashmap) to duplicate these relationships
	other test-cases like multi-oom don't need this feature */
	const int MAPLEN = 10; 
	struct MapElem map[10];
	
	/* index for filling map */ 
	int dupCount = 0;		

	/* file_descriptor_table을 순회 */
	for (int i = 0; i < FDCOUNT_LIMIT; i++)
	{
		struct file *file = parent->file_descriptor_table[i];
		if (file == NULL)
			continue;

		/* Project2-extra) linear search on key-pair array
		If 'file' is already duplicated in child, don't duplicate again but share it */
		bool found = false;
		for (int j = 0; j < MAPLEN; j++)
		{
			if (map[j].key == file)
			{
				found = true;
				current->file_descriptor_table[i] = map[j].value;
				break;
			}
		}
		if (!found)
		{
			struct file *new_file;
			if (file > 2)
				new_file = file_duplicate(file);
			else
				 // 1 STDIN, 2 STDOUT
				new_file = file;

			current->file_descriptor_table[i] = new_file;
			if (dupCount < MAPLEN)
			{
				map[dupCount].key = file;
				map[dupCount++].value = new_file;
			}
		}
	}


	current->fdidx = parent->fdidx;
	sema_up(&current->fork_sema);
	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	current -> exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	// thread_exit ();
}

// /* Switch the current execution context to the f_name.
//  * Returns -1 on fail. */
// int
// process_exec (void *f_name) {
// 	char *file_name = f_name;
// 	bool success;
	
// 	/* We cannot use the intr_frame in the thread structure.
// 	 * This is because when current thread rescheduled,
// 	 * it stores the execution information to the member. */
// 	struct intr_frame _if;
// 	_if.ds = _if.es = _if.ss = SEL_UDSEG;
// 	_if.cs = SEL_UCSEG;
// 	_if.eflags = FLAG_IF | FLAG_MBS;

// 	/* We first kill the current context */
// 	process_cleanup ();

// 	/* argument parsing */
// 	char *argv[30];
// 	int argc = 0;

// 	char *token, *save_ptr;
// 	token = strtok_r(file_name, " ", &save_ptr);
// 	while (token != NULL)
// 	{
// 		/* 공백 기준으로 명령어 나누어 리스트로 조합 */
// 		argv[argc] = token;
// 		token = strtok_r(NULL, " ", &save_ptr);
// 		argc++;
// 	}
	
// 	/* And then load the binary */
// 	success = load (file_name, &_if);
	
// 	/* If load failed, quit. */
// 	if (!success)
// 	{
// 		palloc_free_page(file_name);
// 		return -1;
// 	}

// 	// Project 2-1. Pass args - load arguments onto the user stack
// 	void **rspp = &_if.rsp;

// 	argument_stack(argv, argc, rspp);
	
// 	_if.R.rdi = argc;
// 	_if.R.rsi = (uint64_t)*rspp + sizeof(void *);

// 	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)*rspp, true);

// 	/* Start switched process. */
// 	do_iret (&_if);
// 	NOT_REACHED ();
// }

// void argument_stack(char **argv, int argc, void **rspp)
// {
// 	// 1. Save argument strings (character by character)
// 	for (int i = argc - 1; i >= 0; i--)
// 	{
// 		int N = strlen(argv[i]);
// 		for (int j = N; j >= 0; j--)
// 		{
// 			char individual_character = argv[i][j];
// 			(*rspp)--;
// 			**(char **)rspp = individual_character; // 1 byte
// 		}
// 		argv[i] = *(char **)rspp; // push this address too
// 	}

// 	// 2. Word-align padding
// 	int pad = (int)*rspp % 8;
// 	for (int k = 0; k < pad; k++)
// 	{
// 		(*rspp)--;
// 		**(uint8_t **)rspp = (uint8_t)0; // 1 byte
// 	}

// 	// 3. Pointers to the argument strings
// 	size_t PTR_SIZE = sizeof(char *);

// 	(*rspp) -= PTR_SIZE;
// 	**(char ***)rspp = (char *)0;

// 	for (int i = argc - 1; i >= 0; i--)
// 	{
// 		(*rspp) -= PTR_SIZE;
// 		**(char ***)rspp = argv[i];
// 	}

// 	// 4. Return address
// 	(*rspp) -= PTR_SIZE;
// 	**(void ***)rspp = (void *)0;
// }

int
process_exec (void *f_name) { // 유저가 입력한 명령어를 수행하도록 프로그램을 메모리에 적재하고 실행하는 함수. 여기에 파일 네임 인자로 받아서 저장(문자열) => 근데 실행 프로그램 파일과 옵션이 분리되지 않은 상황.
	/* 수정 */
	char *file_name = f_name; // f_name은 문자열인데 위에서 (void *)로 넘겨받음! -> 문자열로 인식하기 위해서 char * 로 변환해줘야.

	bool success;

	char file_name_address[128]; 	// 원본 문자열을 파싱하면 다른 함수에서 원본 문자열을 쓸 수 있으므로 따로 복사본 만들어줌
									// 지역변수이므로 스택에 할당됨 (함수의 호출과 함께 할당, 호출 완료 시 소멸)

	memcpy(file_name_address, file_name, strlen(file_name)+1); // strlen에 +1? => 원래 문자열에는 \n이 들어가는데 strlen에서는 \n 앞까지만 읽고 끝내기 때문. 전체를 들고오기 위해 +1

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */

	struct intr_frame _if; 					// 이전에 레지스터에 작업하던 context(레지스터값 포함)를 인터럽트가 들어왔을 때 
											// switching 하기 위해 intr_frame 내 구조체 멤버에 담아놓고 스택에 저장하기 위한 구조체
	_if.ds = _if.es = _if.ss = SEL_UDSEG;	// data_segment, more_data_seg, stack_seg
	_if.cs = SEL_UCSEG;						// code_segment
	_if.eflags = FLAG_IF | FLAG_MBS;		// cpu_flag

	/* We first kill the current context */
	process_cleanup ();
	// 새로운 실행 파일을 현재 스레드에 담기 전에 먼저 현재 process에 담긴 context를 지워준다.
	// 지운다? => 현재 프로세스에 할당된 page directory를 지운다는 뜻.

	/* And then load the binary */
	success = load (file_name, &_if); // file_name, _if를 현재 프로세스에 load. (메모리에 올린다는 뜻)
	// success는 bool type이니까 load에 성공하면 1, 실패하면 0 반환.
	// 이때 file_name: f_name의 첫 문자열을 parsing하여 넘겨줘야 한다!

	if (!success){
		return -1;
	}

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true); // 유저 스택에 담기는 값을 확인하려고 메모리 안에 있는 걸 16진수로 값을 보여줌

	/* If load failed, quit. */
	palloc_free_page (file_name); // file_name: 프로그램 파일 받기 위해 만든 임시변수. 
								  // palloc()은 load() 함수 내에서 file_name을 메모리에 올리는 과정에서 page allocation을 해줌
								  // 따라서 load 끝나면 메모리 반환
	if (!success)
		return -1;
	
	/* Start switched process. */
	do_iret (&_if); // 기존까지 작업했던 context를 intr_frame에 담는 과정
	NOT_REACHED ();

}



/* 인자를 stack에 올린다 */
void argument_stack(char **argv, int argc, struct intr_frame *if_) { // if_는 인터럽트 스택 프레임 -> 여기에다 쌓는다.

	/* insert arguments' address */
	char *arg_address[128];

	// 거꾸로 삽입 -> 스택은 반대 방향으로 확장하기 때문!

	/* 맨 끝 NULL값 (arg[4]) 제외하고 스택에 저장 (arg[0]~arg[3]) */
	for (int i = argc-1; i >= 0; i--) {
		int argv_len = strlen(argv[i]);
		/*
		if_ -> rsp: 현재 user stack에서 현재 위치를 가리키는 스택 포인터
		각 인자에서 인자 크기(argv_len)를 읽고 (이때 각 인자에 sentinel이 포함되어 있으니 +1 - strlen에서는 sentinel 빼고 읽음)
		그 크기만큼 rsp를 내려준다. 그 다음 빈 공간만큼 memcpy를 해준다.
		*/
		if_->rsp = if_->rsp - (argv_len+1);
		memcpy(if_->rsp, argv[i], argv_len+1); // argv[i]의 메모리에 있는 값을 artv_len+1의 길이만큼 if_->rsp에 복사해서 붙여넣는 함수 
		arg_address[i] = if_->rsp; // arg_address 배열에 현재 문자열 시작 주소 위치를 저장
	}

	/* word-align: 8의 배수 맞추기 위해 padding 삽입 */
	while (if_->rsp % 8 != 0) {
		if_->rsp--; // 주소값을 1 내리고
		*(uint8_t *) if_->rsp = 0; // 데이터에 0 삽입 -> 8 바이트 저장
	}


	/* 주소값 자체를 삽입 (센티넬 포함해서 넣기) */
	for (int i = argc; i >= 0; i--) {
		// 여기서는 NULL 값 포인터도 같이 넣는다.
		if_->rsp = if_->rsp - 8; // 8바이트만큼 내리고 (64비트 운영체제의 경우 한 번에 처리할 수 있는 데이터 양이 8바이트)
		if (i == argc) { // 가장 위에는 NULL이 아닌 0을 넣음
			memset(if_->rsp, 0, sizeof(char**)); // 메모리의 내용(값)을 원하는 크기만큼 특정 값으로 세팅
												 // 세팅하고자 하는 메모리 주소, 메모리에 세팅하고자 하는 값, 바이트 단위로 메모리의 크기 한 조각 단위의 길이
												 // 성공 시 첫번째 인자로 들어간 ptr 반환, 실패 시 NULL 반환
		} else { // 나머지에는 arg_address 안에 들어있는 "값" 가져오기
			memcpy(if_->rsp, &arg_address[i], sizeof(char**)); // char 포인터의 크기 : 8바이트
		}
	}

	// /* fake return address */
	// if_->rsp = if_->rsp - 8; // void 포인터도 8바이트 크기
	// memset(if_->rsp, 0, sizeof(void *));

	// if_-> R.rdi = argc;			// main 함수에서 argc
	// if_-> R.rsi = if_->rsp + 8; // fake_address 바로 위 : arg_address 맨 앞 가리키는 주소값 // rsi+8

	if_ -> R.rsi = if_->rsp;
	if_ -> R.rdi = argc;

	/* fake return address */
	if_->rsp = if_->rsp - 8; // void 포인터도 8바이트 크기
	memset(if_->rsp, 0, sizeof(void *));

}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// for(int i = 0 ; i<10000000; i++);
	
	// return -1;

	struct thread *child = get_child(child_tid);

	if(child == NULL)
		return -1;

	/* 자식 프로세스가 종료할때 까지 대기 */
	sema_down(&child->wait_sema);

	/* 자식으로 부터 종료인자를 전달 받고 리스트에서 삭제 */
	int exit_status = child->exit_status;
	list_remove(&child->child_elem);
	
	/* 자식 프로세스 종료 상태인자 받은 후 자식 프로세스 종료하게 함 */
	sema_up(&child->free_sema);

	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	
	// P2-4 CLose all opened files
	for (int i = 0; i < FDCOUNT_LIMIT; i++)
	{
		close(i);
	}

	/* thread_create에서 할당한 페이지 할당 해제 */
	palloc_free_multiple(curr->file_descriptor_table, FDT_PAGES); 

	/* 현재 프로세스가 실행중인 파일 종료 */
	file_close(curr->running);

	/* 현재 프로세스의 자원 반납 */
	process_cleanup ();

	/* 부모 프로세스가 자식 프로세스의 종료상태 확인하게 함 */
	sema_up(&curr->wait_sema);
	
	/* 부모 프로세스가 자식 프로세스 종료인자 받을때 까지 대기 */
	sema_down(&curr->free_sema);
	
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	t->running = file;
	
	/* 현재 오픈한 파일에 다른내용 쓰지 못하게 함 */
	file_deny_write(file);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

struct thread *get_child(int pid)
{
	struct thread *cur = thread_current();
	struct list *child_list = &cur->child_list;

#ifdef DEBUG_WAIT
	printf("\nparent children # : %d\n", list_size(child_list));
#endif

	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid)
			return t;
	}	
	return NULL;
}