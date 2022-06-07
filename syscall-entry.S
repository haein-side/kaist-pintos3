#include "threads/loader.h"

.text
.globl syscall_entry
.type syscall_entry, @function
syscall_entry:
	movq %rbx, temp1(%rip)
	movq %r12, temp2(%rip)     /* callee saved registers */
	movq %rsp, %rbx            /* Store userland rsp    */
	movabs $tss, %r12
	movq (%r12), %r12
	movq 4(%r12), %rsp         /* Read ring0 rsp from the tss - 커널 모드로 진입하여 ring0의 특권 가짐 (가리키는 메모리 영역 달라짐으로써) */
	/* Now we are in the kernel stack - rsp가 가리키는 kernel stack에 push */
	/* PUSH [OPERAND] : kernel stack에 OPERAND의 값(user의 inter. frame)을 저장 */
	/* 유저의 inter_frame 정보들을 커널의 stack에 옮겨줌 */
	push $(SEL_UDSEG)      /* if->ss */
	push %rbx              /* if->rsp */
	push %r11              /* if->eflags */
	push $(SEL_UCSEG)      /* if->cs */
	push %rcx              /* if->rip */
	subq $16, %rsp         /* skip error_code, vec_no 스택포인터 rsp를 16만큼 감소, 스택 공간을 16 byte만큼 확보 */
	push $(SEL_UDSEG)      /* if->ds */
	push $(SEL_UDSEG)      /* if->es */
	push %rax			   /* 시스템콜 넘버 - rax 값을 스택에 push */
	movq temp1(%rip), %rbx
	push %rbx
	pushq $0
	push %rdx
	push %rbp
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	pushq $0 /* skip r11 */
	movq temp2(%rip), %r12
	push %r12
	push %r13
	push %r14
	push %r15
	movq %rsp, %rdi

check_intr:
	btsq $9, %r11          /* Check whether we recover the interrupt */
	jnb no_sti
	sti                    /* restore interrupt */
no_sti:
	movabs $syscall_handler, %r12
	call *%r12			   /* syscall_handler 함수 주소로 동작, stack에 다음에 실행할 명령줄의 주소값을 저장 */
	/* POP [OPERAND] : kernel stack 맨 위에 저장된 값을 OPERAND에 저장 */
	popq %r15			   /* syscall_handler 가 끝나면 popq 실행 - rsp가 가리키는 kernel stack에서 pop */
	popq %r14			   /* stack의 맨 위에 저장된 값을 가져와서 %r14에 저장 */
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rsi
	popq %rdi
	popq %rbp
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	addq $32, %rsp		   /* 스택포인터 rsp를 32만큼 증가, 스택 공간을 32 byte만큼 내림 */
	popq %rcx              /* if->rip */
	addq $8, %rsp
	popq %r11              /* if->eflags */
	popq %rsp              /* if->rsp */
	sysretq

.section .data
.globl temp1
temp1:
.quad	0
.globl temp2
temp2:
.quad	0
