#include "userprog/tss.h"
#include <debug.h>
#include <stddef.h>
#include "userprog/gdt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "intrinsic.h"

/* The Task-State Segment (TSS).
 *
 *  Instances of the TSS, an x86-64 specific structure, are used to
 *  define "tasks", a form of support for multitasking built right
 *  into the processor.  However, for various reasons including
 *  portability, speed, and flexibility, most x86-64 OSes almost
 *  completely ignore the TSS.  We are no exception.
 *
 *  Unfortunately, there is one thing that can only be done using
 *  a TSS: stack switching for interrupts that occur in user mode.
 * 		   유저모드에서 일어난 인터럽트를 위한 스택 스위칭을 위해 TSS가 사용됨
 *  When an interrupt occurs in user mode (ring 3), the processor
 *  consults the rsp0 members of the current TSS to determine the
 *  stack to use for handling the interrupt.  Thus, we must create
 *  a TSS and initialize at least these fields, and this is
 *  precisely what this file does.
 *  사용자 모드(링 3)에서 인터럽트가 발생하면 프로세서는 
 *  현재 TSS의 rsp0 구성원을 참조하여 인터럽트를 처리하는 데 사용할 스택을 결정합니다.
 *
 *  When an interrupt is handled by an interrupt or trap gate
 *  (which applies to all interrupts we handle), an x86-64 processor
 *  works like this:
 *
 *    - If the code interrupted by the interrupt is in the same
 *      ring as the interrupt handler, then no stack switch takes
 *      place.  This is the case for interrupts that happen when
 *      we're running in the kernel.  The contents of the TSS are
 *      irrelevant for this case.
 *		같은 ring에 있는 상태에서 interrupt가 일어났을 때는 stack switching이 일어나지 않음
 * 		=> TSS는 관여 X
 *      ex. interrupt happened runnning in the kernel
 * 	
 *    - If the interrupted code is in a different ring from the
 *      handler, then the processor switches to the stack
 *      specified in the TSS for the new ring.  This is the case
 *      for interrupts that happen when we're in user space.  It's
 *      important that we switch to a stack that's not already in
 *      use, to avoid corruption.  Because we're running in user
 *      space, we know that the current process's kernel stack is
 *      not in use, so we can always use that. 
 *      현재 유저 스레드를 실행시켜준 커널 스택이 있을 것. 그것을 이용하라는 것.
 *       Thus, when the scheduler switches threads, it also changes the TSS's
 *      stack pointer to point to the new thread's kernel stack.
 *      (The call is in schedule in thread.c.)
 *      다른 ring에 있는 상태에서 interrupt가 일어났을 때는 stack switching이 일어남
 *      => TSS 관여 O
 *      ex. interrupt happened in user space */

/* Kernel TSS. */
struct task_state *tss;

/* Initializes the kernel TSS. */
void
tss_init (void) {
	/* Our TSS is never used in a call gate or task gate, so only a
	 * few fields of it are ever referenced, and those are the only
	 * ones we initialize. */
	tss = palloc_get_page (PAL_ASSERT | PAL_ZERO);
	tss_update (thread_current ());
}

/* Returns the kernel TSS. */
struct task_state *
tss_get (void) {
	ASSERT (tss != NULL);
	return tss;
}

/* Sets the ring 0 stack pointer in the TSS to point to the end
 * of the thread stack. */
// TSS는 링 스위칭 동안 커널 스택 포인터를 찾기 위해 여전히 존재
// 사용자 프로세스가 인터럽트 핸들러에 들어갈 때 하드웨어가 커널 스택 포인터를 찾기 위해 tss를 참조
void
tss_update (struct thread *next) {
	ASSERT (tss != NULL);
	tss->rsp0 = (uint64_t) next + PGSIZE;
}
