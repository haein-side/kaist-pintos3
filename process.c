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
#include "userprog/syscall.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
void argument_stack(char **argv, int argc, struct intr_frame *if_);
struct thread *get_child(int pid);

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
/* 새 프로그램을 실행시킬 새 커널 스레드를 딱 한 번 만듦
   palloc으로 커널 가용 페이지 할당 */
tid_t
process_create_initd (const char *file_name) { // filename = "args-single onearg"
	char *fn_copy;
	tid_t tid;
	// strtok_r로 자르기 전의 file_name: args-single onearg

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0); // 새 프로세스 실행시키므로 하나의 커널 가용 페이지를 할당하고 그 커널 페이지의 가상 주소를 리턴
	
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE); // fn_copy 주소 공간에 file_name을 복사해 넣어주고, 최대 4kb까지 복사(임의로 준 크기)

	char *save_ptr;
	/* thread_create 시 스레드 이름을 실행 파일과 동일하게 만들어 주기 위해 parsing 진행 */
	strtok_r(file_name, " ", &save_ptr);  // file_name: "args-single", save_ptr: "onearg"
	
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy); // file_name: "args-single", fn_copy: "args-single onearg"
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
/* 첫번째 유저 프로세스를 실행하기 위해 초기화(process_exec)를 해주는 함수 @ 커널 모드
   그 다음부터는 fork()를 통해 프로세스를 생성하게 되므로
   첫 프로세스를 생성할 때만 initd()를 사용 */
/* file_name 함수에 인자로 받아온 인자들을 넣어줌 */
/* 해당 프로세스를 초기화하고 process_exec() 함수를 실행 */
static void
initd (void *f_name) {
	// printf("initd에서 %s\n", f_name); args-single onearg
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init (); // 프로세스 초기화

	if (process_exec (f_name) < 0) {	// process_exec 함수 실행
		PANIC("Fail to launch initd\n");
	}
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) { // 부모 프로세스 if_
	/* Clone current thread to new thread.*/
	struct thread *parent = thread_current(); // 커널 스레드 (현재 부모 스레드)

	/* 전달받은 intr_frame을 parent_if에 복사 */
	memcpy(&parent->parent_if, if_, sizeof(struct intr_frame)); // 부모 스레드의 정보를 담은 자식에게 넘겨줄 itrp frame
	
	/* __do_fork를 실행하는 스레드 생성, 현재 스레드를 인자로 넘겨줌 */
	/* 자식 스레드는 ready list, 부모 스레드는 sema_down()에서 thread_block()으로 주도권 뺏김 
	=> 자식이 주도권 잡으면 __do_fork 실행됨 */
	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, parent); // 전달받은 thread_name으로 __do_fork()를 진행
																	 // 자식 스레드한테 부모 스레드의 정보를 그대로 줌

	if (tid == TID_ERROR) {
		return TID_ERROR;
	}

	struct thread *child = get_child(tid); // 생성해준 자식 스레드 구조체
	sema_down(&child->fork_sema);
	// get_child()를 통해 해당 p fork_sema 값이 1이 될 때까지
	// (=자식 스레드 load가 완료될 때까지)를 기다렸다가 끝나면 pid를 반환

	if (child->exit_status == -1) {
		return TID_ERROR;
	}

	return tid;
}

/*
인자로 넣은 pid에 해당하는 자식 스레드의 구조체를 얻은 후 
sema_fork 값이 1이 될 때 (== 자식 스레드의 load가 완료될 때, 즉 sema가 풀렸을 때)까지
기다렸다가 pid를 반환
*/
/*  
현재 실행 중인 프로세스의 자식 프로세스 중에서,
인자로 받은 pid와 같은 tid를 갖는 자식 프로세스를 찾아 리턴 
-> 현재 실행 중인 프로세스가 부모 프로세스이므로 자식 스레드가 load 완료된 이후에 
sema_up이 일어났을 때 부모 프로세스가 실행될 수 있는 상황에서 get_child가 실행 가능하다는 것
*/
struct thread *get_child(int pid) { // 생성해준 자식 스레드의 tid
	struct thread *cur = thread_current(); // 부모가 아직까진 현재 스레드
	struct list *child_list = &cur->child_list; // 부모의 child list

	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e)){
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid) {
			return t; // 자식 스레드 구조체를 리턴
		}
	}
	
	return NULL;
}
 
#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
/* 부모의 page table을 복제하기 위해 page table을 생성한다. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	/* 1. 부모 페이지가 kernel에 있으면 fork 요청을 해주면 안 됨 (유저 영역일 때만 fork 요청해줘야) */
	if is_kernel_vaddr(va) { 
		return true;
	}
	/* 2. Resolve VA from the parent's page map level 4. */
	/* 2. 부모 스레드 내 멤버인 pml4를 이용해 부모 페이지를 불러옴 */
	parent_page = pml4_get_page (parent->pml4, va);
	// 인자로 받은 유저가상메모리에 매핑되는 커널 VA를 리턴
	// 부모 스레드의 유저 VA를 받아 커널 스레드인 parent가 가지는 페이지 테이블 시작 포인터인 pml4에서
	// 매핑되는 커널 VA를 리턴받는 것
	if (parent_page == NULL){
		return false;
	}

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	/* 3. 새로운 PAL_USER 페이지를 할당하고 newpage에 저장 */
	newpage = palloc_get_page(PAL_USER); 
			  // Obtains a single free page and returns its kernel virtual address.
	if (newpage == NULL) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	/* 4. 부모 페이지를 복사해 3에서 새로 할당받은 페이지에 넣어준다. 
		  이때 부모 페이지가 writable인지 아닌지 확인하기 위해 is_writable() 함수를 이용 */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	/* 페이지 생성에 실패하면 에러 핸들링이 동작하도록 false를 리턴 */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	
	return true;
}
#endif

// project 2 - extra
struct MapElem {
	uintptr_t key;
	uintptr_t value;
};

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 부모의 프로세스를 그대로 실행하기 위해 부모 프로세스의 실행 context를 복사하는 함수
 * 부모 프로세스로부터 파일, pml4 table, 어디까지 진행했었는지 instruction 정보를 복사(메모리에 올려야)해야 함
 * user stack을 가져오기 위해 커널 스택 내에 intr_frame if_를 만들고 거기다가 parent_if라는 유저 스택 값을 복사해줌
 */
static void
__do_fork (void *aux) { // aux로 부모 스레드(parent)를 가리키는 주소 받음. 현재 CPU 점유권은 자식 스레드가 가짐.
	struct intr_frame if_;

	struct thread *parent = (struct thread *) aux; // parent : 부모 스레드 가리킴 (parent_if가 부모의 _if 가리킴)
	struct thread *current = thread_current ();    // current : 자식 스레드 가리킴 (자식 스레드가 cpu 점유권 가짐)

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* process_fork에서 복사 해두었던 intr_frame */
	parent_if = &parent->parent_if;
	
	/* 1. Read the cpu context to local stack. */
	/* 부모의 intr_frame을 지역변수 if_에 복사 => user stack에 있는 값을 가져오기 위해 커널 스택 내에 if_ 만든 것 */
	/* kernel stack 내에 user_context를 가짐 */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 자식의 intr_frame에 리턴값(rax)에 0을 넣어둠 */
	if_.R.rax = 0;

	/* 2. Duplicate Page table */
	/* 파일에 접근하기 위한 페이지 테이블도 복제해줌 */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	/* 부모 프로세스의 page table entry를 하나씩 자식 프로세스의 pte에 복사해줌 */
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;

#endif
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	if (parent->fdidx == FDCOUNT_LIMIT) {
		goto error;
	}

	/* dup2 코드 */
	const int MAPLEN = 10;
	struct MapElem map[10];
	int dup_count = 0;

	for (int i = 0; i < FDCOUNT_LIMIT; i++) {
		struct file *file = parent->file_descriptor_table[i];
		if (file == NULL){
			continue;
		}

		bool found = false;

		for (int j = 0; j < MAPLEN; j++) {
			if (map[j].key == file){
				found = true;
				current->file_descriptor_table[i] = map[j].value;
				break;
			}
		}
		if (!found) {
			struct file *new_file;
			if (file > 2)
				new_file = file_duplicate(file);
			else
				new_file = file;
			current->file_descriptor_table[i] = new_file;
			if (dup_count < MAPLEN) {
				map[dup_count].key = file;
				map[dup_count++].value = new_file;
			}
		}

	}
	current->fdidx = parent->fdidx;
	/* 잠들어 있던 부모 스레드 깨움! */
	sema_up(&current->fork_sema);

	/* 부모의 intr-frame 정보를 복사하고 child의 메모리를 적재한 정보를 담은 if_를 실제 레지스터에 심는다 */
	if (succ)
		do_iret (&if_);
error:
	current->exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	exit(TID_ERROR);
	// thread_exit ();
	
	/* dup2 제외 코드 */
	/* 자식 프로세스의 FDT를 부모 FDT와 동일하게 해줌 */
// 	current->file_descriptor_table[0] = parent->file_descriptor_table[0];
// 	current->file_descriptor_table[1] = parent->file_descriptor_table[1];

// 	for (int i = 2; i < FDCOUNT_LIMIT; i++){
// 		struct file *f = parent->file_descriptor_table[i];
// 		if (f == NULL) {
// 			continue;
// 		}
// 		current->file_descriptor_table[i] = file_duplicate(f);
// 	}
// 	current->fdidx = parent->fdidx;
// 	sema_up(&current->fork_sema);

// 	/* Finally, switch to the newly created process. */
// 	if (succ)
// 		do_iret (&if_);
// error:
// 	current->exit_status = TID_ERROR;
// 	sema_up(&current->fork_sema);
// 	exit(TID_ERROR);
// 	// thread_exit ();

}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/* 현재 실행되고 있는 스레드를 f_name에 해당하는 명령을 실행하기 위해 context switching */
int
process_exec (void *f_name) { // 유저가 입력한 명령어를 수행하도록 프로그램을 메모리에 적재하고 실행하는 함수. 여기에 파일 네임 인자로 받아서 저장(문자열) => 근데 실행 프로그램 파일과 옵션이 분리되지 않은 상황.
	
	char *file_name = f_name; // f_name은 문자열인데 위에서 (void *)로 넘겨받음! -> 문자열로 인식하기 위해서 char * 로 변환해줘야.

	bool success;

	char file_name_address[128]; 	// 원본 문자열을 파싱하면 다른 함수에서 원본 문자열을 쓸 수 있으므로 따로 복사본 만들어줌
									// 지역변수이므로 스택에 할당됨 (함수의 호출과 함께 할당, 호출 완료 시 소멸)

	memcpy(file_name_address, file_name, strlen(file_name)+1); // strlen에 +1? => 원래 문자열에는 \n이 들어가는데 strlen에서는 \n 앞까지만 읽고 끝내기 때문. 전체를 들고오기 위해 +1
	// memcpy : 메모리의 일부분을 복사
	// file_name이 가리키는 곳으로부터 strlen(file_name)+1만큼을 file_name_address가 가리키는 곳에 복사

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */

	/* 유저 모드에서 사용하는 인터럽트 프레임에 대한 자료구조 초기화 (값을 넣어주진 않음) */
	struct intr_frame _if; 					// 이전에 레지스터에 작업하던 context(레지스터값 포함)를 인터럽트가 들어왔을 때 
											// switching 하기 위해 intr_frame 내 구조체 멤버에 담아놓고 스택에 저장하기 위한 구조체
	_if.ds = _if.es = _if.ss = SEL_UDSEG;	// data_segment, more_data_seg, stack_seg : 유저 메모리의 데이터(쌓여있는 스택 값 등)
	_if.cs = SEL_UCSEG;						// code_segment : 코드 선택자로 유저 메모리에 있는 데이터
	_if.eflags = FLAG_IF | FLAG_MBS;		// cpu_flag 

	/* We first kill the current context */
	process_cleanup ();
	// 새로운 실행 파일을 현재 스레드에 담기 전에 먼저 현재 process에 담긴 context를 지워준다.
	// 지운다? => 현재 프로세스에 할당된 page directory를 지운다는 뜻.

	/* And then load the binary */
	success = load (file_name, &_if); // file_name, _if를 load. (ELF 목적파일 형태로 메모리에 올린다는 뜻)

	// 사용자 프로세스 작업을 수행하기 위한 인터럽트 프레임 구조체 내 정보를 커널 스택에 쌓음 (목적 파일 형태로) 
	// success는 bool type이니까 load에 성공하면 1, 실패하면 0 반환.
	// 이때 file_name: f_name의 첫 문자열을 parsing하여 넘겨줘야 한다!

	if (!success){
		return -1;
	} 

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true); // 유저 스택에 담기는 값을 확인하려고 메모리 안에 있는 걸 16진수로 값을 보여줌
	// load()에서 argument_stack으로 인자들을 유저 스택에 삽입

	/* If load failed, quit. */
	palloc_free_page (file_name); // file_name: 프로그램 파일 받기 위해 만든 임시변수. 
								  // palloc()은 load() 함수 내에서 file_name을 메모리에 올리는 과정에서 page allocation을 해줌
								  // 따라서 load 끝나면 메모리 반환
	
	/* Start switched process. */
	do_iret (&_if); // 기존까지 작업했던 context를 인터럽트 프레임인 _if에 담아뒀는데, _if 구조체 내 값으로 레지스터 값을 수정
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
/* 부모 스레드는 자식 프로세스가 실행되는 것을 기다렸다가
   자식 프로세스가 종료되면 시그널을 받아 부모 스레드가 종료되어야 함
   그러나 바로 종료되어 버리므로 자식 프로세스가 실행되지 못함
   process_wait()에 무한 루프를 넣어 자식 프로세스가 실행될 수 있게 해 줌 */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// while(1) {}; // 자식 프로세스가 실행될 수 있도록 무한루프 추가
	// for (int i = 0; i < 100000000; i++); // 테스트를 위해 잠시 무한루프 해제 -> fork 완성 전까지만
	// return -1;

	struct thread *child = get_child(child_tid);
	if (child == NULL)
		return -1;

	// parent waits until child signals(sema_up) after its execution
	// 여기서는 parent가 잠듦
	sema_down(&child->wait_sema);

	// 여기서부터는 깨어났다.
    // 깨어나면 child의 exit_status를 얻는다
	int exit_status = child->exit_status;
	// child를 부모 list에서 지운다.
	list_remove(&child->child_elem);
	// 내가 받았음을 전달하는 sema
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
	for (int i = 0; i < FDCOUNT_LIMIT; i++){
		close(i);
	}
	// for multi-oom(메모리 누수)
	palloc_free_multiple(curr->file_descriptor_table, FDT_PAGES);
	
	// running이 NULL일 때는 file_close를 할 필요가 없음
	// 모든 alarm-single 같은 것들이 다 userprog로 들어와서 process_exit으로 들어옴
	// 이때는 running이 NULL임 -> file_close할 필요 없음
	if (curr->running != NULL) {
		 // for rox- (실행중에 수정 못하도록)
		file_close(curr->running);
	}

	process_cleanup();
	// 종료되었다고 기다리고 있는 부모 thread에게 signal 보냄-> sema_up에서 val을 올려줌
	sema_up(&curr->wait_sema);
	// 부모에게 exit_status가 정확히 전달되었는지 확인(wait)
	// 부모가 자식의 exit_status를 받고 child에서 자식을 제대로 지우면 sema_up(&child->free_sema)을 통해 자식이 진짜 사라지도록 함 
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
		 * that's been freed (and cleared).
		 * 순서가 중요한 이유가 나와 있으나 이해 잘 못함
		 *  */
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
/* 프로그램을 메모리에 적재
 * ELF 파일 포맷에 따라 메모리에 실행 파일을 탑재한다. 
 * 파일을 open하고 ELF 파일 헤더 정보를 저장
 * 프로그램 배치 정보를 읽어 파일의 데이터를 메모리에 탑재
 * 스택, 데이터, 코드를 user pool에 생성하고 초기화
 * cpu의 다음 명령어 주소를 해당 프로그램의 엔트리 주소(_start() 함수)로 설정
 */
static bool
load (const char *file_name, struct intr_frame *if_) { // file_name으로 함수 이름만 들어와야 원하는 작업 완료 가능

	// printf("filename은 ? %s\n", file_name);
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* command line parsing */
	// char *arg_list[128];
	// char *token, *save_ptr;
	// int argc = 0;

	// token = strtok_r(file_name, " ", &save_ptr); // 첫번째 이름
	// arg_list[token_count] = token;

	// while (token != NULL) {
	// 	token = strtok_r (NULL, " ", &save_ptr);
	// 	token_count++;
	// 	arg_list[token_count] = token;
	// }

	char *argv[64];
	char *token, *save_ptr;
	int argc = 0;
	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
		argv[argc] = token;
		argc += 1;
	}

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create (); // 페이지 디렉토리 생성
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ()); // 페이지 테이블 활성화

	/* Open executable file. */
	file = filesys_open (file_name); // 프로그램 파일 open: load하고 싶은 파일(함수)을 open한다.
									 // ELF 파일 포맷에 따라 메모리에 ELF 파일 헤더 정보를 저장
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name); 
		goto done;
	}

	/* denying writes to executable */
	t->running = file;
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
		// ELF 파일의 헤더 정보를 읽어와 저장
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
					// Code, Data 영역을 User Pool에 만듦
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
	// "다음" CPU의 인스트럭션을 가리키는 RIP 레지스터가
	// 실행 파일에서 읽어온 "해당 프로그램의 entry"(ELF 파일의 헤더에 저장되어 있던)를 가리킨다.
	// 유저 영역에서 다음에 실행할 PC로 rip 수정해줌 -> 바로 해당 유저 영역의 instruction 실행하도록 
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	/* Argument parsing */
	// argument_stack(arg_list, token_count, if_); 
	// 인터럽트 프레임 내 구조체 중 rsp가 가리키는 스택 포인터에 인자를 넣어주기
	argument_stack(argv, argc, if_); // 인자값을 스택에 올림

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// 파일이 열려 있어야 하는 상태이므로 file_close() 주석처리
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
/* 최소한의 유저 스택 세팅 */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK; // 커널 스택을 가리키던 rsp를 USER_STACK으로 갱신함으로써 유저 프로그램 실행 가능
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