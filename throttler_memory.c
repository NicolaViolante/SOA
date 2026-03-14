#include <linux/module.h>
#include <linux/kprobes.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include "throttler_internal.h"
#include "./lib/vtpmo.h"

extern int sys_vtpmo(unsigned long vaddr);

#define ADDRESS_MASK 0xfffffffffffff000
#define START           0xffffffff00000000ULL
#define MAX_ADDR        0xfffffffffff00000ULL
#define FIRST_NI_SYSCALL    134
#define SECOND_NI_SYSCALL   174
#define THIRD_NI_SYSCALL    182
#define FOURTH_NI_SYSCALL   183
#define FIFTH_NI_SYSCALL    214
#define SIXTH_NI_SYSCALL    215
#define SEVENTH_NI_SYSCALL  236

unsigned long **hacked_syscall_tbl = NULL;

static inline void write_cr0_forced(unsigned long val){ //per forzare scrittura su cr0
    unsigned long __force_order;  //lo usiamo per evitare riordino istruzioni
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(unsigned long cr0){ 
  write_cr0_forced(cr0); //ripristino protezioni di memoria
}

static inline void unprotect_memory(unsigned long cr0){ 
  write_cr0_forced(cr0 & ~X86_CR0_WP); //modifica solo del bit Write Protect
}

static inline void write_cr4_forced(unsigned long val){ //per forzare scrittura su cr0
    unsigned long __force_order; //lo usiamo per evitare riordino istruzioni
    asm volatile("mov %0, %%cr4" : "+r"(val), "+m"(__force_order));
}

static inline void conditional_cet_disable(unsigned long cr4){
#ifdef X86_CR4_CET
    if (cr4 & X86_CR4_CET) // per permettere di fare update su cr0
            write_cr4_forced(cr4 & ~X86_CR4_CET);
#endif
}

static inline void conditional_cet_enable(unsigned long cr4){
#ifdef X86_CR4_CET
    if (cr4 & X86_CR4_CET) 
            write_cr4_forced(cr4); //ripristino cr4
#endif
}

void begin_syscall_table_hack(unsigned long *cr0, unsigned long *cr4){
    preempt_disable(); //durante tutta la durata dell'hack della memoria il thread non deve essere preemptable
    *cr0 = read_cr0(); 
    *cr4 = native_read_cr4();
    conditional_cet_disable(*cr4); 
    unprotect_memory(*cr0);
}
void end_syscall_table_hack(unsigned long cr0, unsigned long cr4){
    protect_memory(cr0); 
    conditional_cet_enable(cr4); 
    preempt_enable();
}

static int good_area(unsigned long * addr){ // evita falsi positivi
    int i;
    for(i=1;i<FIRST_NI_SYSCALL;i++){ if(addr[i] == addr[FIRST_NI_SYSCALL]) return 0; }
    return 1;
}

static int validate_page(unsigned long *addr){
    int i = 0;
    unsigned long page = (unsigned long) addr;
    unsigned long new_page = (unsigned long) addr;
    for(; i < PAGE_SIZE; i+=sizeof(void*)){
        new_page = page+i+SEVENTH_NI_SYSCALL*sizeof(void*);
        if(((page+PAGE_SIZE) == (new_page & ADDRESS_MASK) ) && sys_vtpmo(new_page) == NO_MAP) break; //controllo se pagina successiva è mappata
        addr = (unsigned long*) (page+i);
        if( ((addr[FIRST_NI_SYSCALL] & 0x3) == 0) //allineamento a 4 byte
          && (addr[FIRST_NI_SYSCALL] != 0x0) // puntatore non vuoto
          && (addr[FIRST_NI_SYSCALL] > 0xffffffff00000000 ) //indirizzo in kernel space (metà alta)
          && (addr[FIRST_NI_SYSCALL] == addr[SECOND_NI_SYSCALL]) 
          && (addr[FIRST_NI_SYSCALL] == addr[THIRD_NI_SYSCALL]) 
          && (addr[FIRST_NI_SYSCALL] == addr[FOURTH_NI_SYSCALL]) 
          && (addr[FIRST_NI_SYSCALL] == addr[FIFTH_NI_SYSCALL]) 
          && (addr[FIRST_NI_SYSCALL] == addr[SIXTH_NI_SYSCALL]) 
          && (addr[FIRST_NI_SYSCALL] == addr[SEVENTH_NI_SYSCALL]) 
          && (good_area(addr))){
            hacked_syscall_tbl = (void*)(addr); //salvataggio indirizzo
            return 1;
        }
    }
    return 0;
}

static void syscall_table_finder(void){
    unsigned long k;
    unsigned long candidate;
    for(k=START; k < MAX_ADDR; k+=PAGE_SIZE){ //scansione memoria pagina per pagina
        candidate = k;
        if((sys_vtpmo(candidate) != NO_MAP)){ // controllo sul mapping
            if(validate_page( (unsigned long *)(candidate) ) ){
              pr_info("%s: syscall table found at %px\n", MODNAME, (void*)(hacked_syscall_tbl));
              break;
             }
        }
    }
}

#define INST_LEN 5
char jump_inst[INST_LEN];
char original_inst[INST_LEN];
unsigned long x64_sys_call_addr;
int offset;
static struct kprobe kp_x64_sys_call = { .symbol_name = "x64_sys_call" };

asm(
"    .text\n"
"    .align 16\n"
"    .global sys_call_trampoline\n"
"    sys_call_trampoline:\n"
"    endbr64\n"
"    mov hacked_syscall_tbl(%rip), %r11\n"
"    mov (%r11, %rsi, 8), %rax\n"
"    jmp __x86_indirect_thunk_rax\n"
);
extern void sys_call_trampoline(void);


int throttler_memory_init(void) {
    unsigned long cr0;
    unsigned long cr4;
    syscall_table_finder(); //ricerca system-call-table
    if(!hacked_syscall_tbl) return -ENOENT;

    if(register_kprobe(&kp_x64_sys_call)){
      pr_err("%s: failed to find x64_sys_call\n",MODNAME);
      return -EFAULT;
    }
      
    x64_sys_call_addr = (unsigned long)kp_x64_sys_call.addr;
    unregister_kprobe(&kp_x64_sys_call); //deregistrazione kprobe non appena trovato indirizzo
    
    memcpy(original_inst, (unsigned char *)x64_sys_call_addr, INST_LEN); //backup che serve in fase di smontaggio
    jump_inst[0] = 0xE9;
    offset = (unsigned long)sys_call_trampoline - x64_sys_call_addr - INST_LEN;
    memcpy(jump_inst + 1, &offset, sizeof(int)); //jump+offset

    begin_syscall_table_hack(&cr0,&cr4);
    memcpy((unsigned char *)x64_sys_call_addr, jump_inst, INST_LEN);
    end_syscall_table_hack(cr0,cr4);
    
    return 0;
}

void throttler_memory_cleanup(void) {
    unsigned long cr0, cr4;
    begin_syscall_table_hack(&cr0,&cr4);
    memcpy((unsigned char *)x64_sys_call_addr, original_inst, INST_LEN); //ripristino byte originali
    end_syscall_table_hack(cr0,cr4);
}
