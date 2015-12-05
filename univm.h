#ifndef _UNIVM_H
#define _UNIVM_H

#include <inttypes.h>
#include <unicorn/unicorn.h>
#include "pluginmain.h"

enum DBGPRINT {
	S_PRINT = 0,
	PRINT = 2,
	FLUSH = 3
};

struct mem_block {
	mem_block() {
		start = 0;
		end = 0;
		req = 0;
		size = 0;
	}
	uint32_t start;
	uint32_t end;
	uint32_t req;
	size_t size;
};

struct mem_map {
	mem_map() {
		items = 0;
	}
	struct mem_block mem_block[1024];
	unsigned int items;
};

typedef enum {
	EAX = 0,
	EBX,
	ECX,
	EDX,
	EBP,
	ESP,
	ESI,
	EDI,
	EIP = 9,
	EFLAGS = 8
};

typedef struct {
	unsigned int regs[16];
} VM_Ctx;

typedef struct {
	unsigned int StackBase;
	unsigned int StackLimit;
} STACKINFO;

extern size_t SizeOfImage;
extern uint64_t BaseAddress;
extern struct mem_map mem_map;
extern uint64_t instructions;
extern uint32_t TIB;
extern bool is_vm_running;

#ifdef __i386__
typedef uint32_t addr_t;
#elif __x86_64__
typedef uint64_t addr_t;
#endif


//menu identifiers
#define MENU_DISASM_VM_EXEC 0
#define MENU_DISASM_VM_STOP 1

//functions
unsigned int GetStackBase();
unsigned int GetStackLimit();
void dump_state(uc_engine *);
static void VM_init();
static void VM_exec();
void mylogprintf(enum DBGPRINT print, const char *format, ...);
void testInit(PLUG_INITSTRUCT* initStruct);
void testStop();
void testSetup();

#endif // _UNIVM_H
