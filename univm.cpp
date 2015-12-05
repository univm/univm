#include <windows.h>
#include <commctrl.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>
#include <pthread.h>
#include <unicorn/unicorn.h>
#include <inttypes.h>
#include <assert.h>

#include "pluginsdk\bridgemain.h"
#include "pluginsdk\TitanEngine\TitanEngine.h"
#include "univm.h"
#include "memory.h"

#define ADDTEXT(REG,x,y) CreateWindowEx(WS_EX_LEFT, "Static", #REG, \
                      WS_VISIBLE | WS_CHILD, \
                      x, y, 37, 24, \
                      hwnd, \
                      NULL, hInstance, NULL);
					  
#define ADDFIELD(x,y) CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "00000000", \
                      WS_VISIBLE | WS_CHILD | ES_LEFT, \
                      x, y, 150, 18, \
                      hwnd, \
                      NULL, hInstance, NULL);

SELECTIONDATA sel;					  
HANDLE WaitForStart;
HWND hwnd;
HWND g_regs[16];
VM_Ctx VM_ctx;
static struct mem_map mem_map;
uc_engine *base;
size_t SizeOfImage;
uint64_t BaseAddress;
uint64_t instructions = 0;
uint32_t TIB = 0;
bool vm_initialized = false;
bool is_vm_running = false;
bool vm_stop_req = false;
uc_engine *uc;
uc_err err;

void mylogprintf(enum DBGPRINT print, const char *format, ...)
{
	static char buff[32768];
	static size_t len = 0;
	va_list args;
	
	if(print == FLUSH && format == NULL)
	{
		_plugin_logputs(buff);
		fflush(stdout);
		
		len = 0;
	}
	else if(print == PRINT)
	{
		char buff2[1024];
		
		va_start(args, format);
		vsnprintf_s(buff2, _countof(buff2), _TRUNCATE, format, args);
		va_end(args);
		
		_plugin_logputs(buff2);
		fflush(stdout);
		
		return;
	}	
	else
	{
		va_start(args, format);
		len += vsnprintf_s(buff+len, _countof(buff)-len, _TRUNCATE, format, args);
		buff[len] = '\0';
		va_end(args);
	}
}

void dump_state(uc_engine *uc)
{
	VM_Ctx VM_ctx_d;
	
	uc_reg_read(uc, UC_X86_REG_EAX, &VM_ctx_d.regs[EAX]);
	uc_reg_read(uc, UC_X86_REG_EBX, &VM_ctx_d.regs[EBX]);
	uc_reg_read(uc, UC_X86_REG_ECX, &VM_ctx_d.regs[ECX]);
	uc_reg_read(uc, UC_X86_REG_EDX, &VM_ctx_d.regs[EDX]);
	uc_reg_read(uc, UC_X86_REG_EBP, &VM_ctx_d.regs[EBP]);
	uc_reg_read(uc, UC_X86_REG_ESP, &VM_ctx_d.regs[ESP]);	
	uc_reg_read(uc, UC_X86_REG_ESI, &VM_ctx_d.regs[ESI]);
	uc_reg_read(uc, UC_X86_REG_EDI, &VM_ctx_d.regs[EDI]);
	uc_reg_read(uc, UC_X86_REG_EIP, &VM_ctx_d.regs[EIP]);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &VM_ctx_d.regs[EFLAGS]);
	
	mylogprintf(S_PRINT, "[UniVM] >>> EAX = 0x%08X\n", VM_ctx_d.regs[EAX]);
	mylogprintf(S_PRINT, "[UniVM] >>> EBX = 0x%08X\n", VM_ctx_d.regs[EBX]);
	mylogprintf(S_PRINT, "[UniVM] >>> ECX = 0x%08X\n", VM_ctx_d.regs[ECX]);
	mylogprintf(S_PRINT, "[UniVM] >>> EDX = 0x%08X\n", VM_ctx_d.regs[EDX]);	
	mylogprintf(S_PRINT, "[UniVM] >>> EBP = 0x%08X\n", VM_ctx_d.regs[EBP]);
	mylogprintf(S_PRINT, "[UniVM] >>> ESP = 0x%08X\n", VM_ctx_d.regs[ESP]);
	mylogprintf(S_PRINT, "[UniVM] >>> ESI = 0x%08X\n", VM_ctx_d.regs[ESI]);
	mylogprintf(S_PRINT, "[UniVM] >>> EDI = 0x%08X\n", VM_ctx_d.regs[EDI]);
	mylogprintf(S_PRINT, "[UniVM] >>> EIP = 0x%08X\n", VM_ctx_d.regs[EIP]);
	mylogprintf(S_PRINT, "[UniVM] >>> EFLAGS = 0x%08X\n", VM_ctx_d.regs[EFLAGS]);

	mylogprintf(FLUSH, NULL);
}

void setupFlagsReg(const REGDUMP regs, uint32_t *flags)
{
	*flags = regs.regcontext.eflags;
	SETBIT(*flags, 1);
	CLRBIT(*flags, 3);
	CLRBIT(*flags, 5);
	CLRBIT(*flags, 8); //trap flag
	
	//mylogprintf(S_PRINT, "Eflags %08x", regs.regcontext.eflags);
}

unsigned int GetStackBase()
{
	unsigned char base[4];
	unsigned int r_base;
	
	assert(TIB != 0);
	
	if(!DbgMemRead((ULONG_PTR)(TIB+4), base, sizeof(base)))
	{
		mylogprintf(PRINT, "[UniVM] Failed to GetStackBase with %d\n", GetLastError());
	}
	
	memcpy(&r_base, base, 4);
	
	return r_base;
}

unsigned int GetStackLimit()
{
	unsigned char limit[4];
	unsigned int r_limit;
	
	assert(TIB != 0);
	
	if(!DbgMemRead((ULONG_PTR)(TIB+8), limit, sizeof(limit)))
	{
		mylogprintf(PRINT, "[UniVM] Failed to GetStackLimit with %d\n", GetLastError());
	}
	
	memcpy(&r_limit, limit, 4);
	
	return r_limit;
}


void setupSegmentRegs(uc_engine *uc)
{
	THREADLIST thrList;
	
	DbgGetThreadList(&thrList);
	TIB = thrList.list[thrList.CurrentThread].BasicInfo.ThreadLocalBase;
	uc_reg_write(uc, UC_X86_REG_FS, &TIB);
	
	mylogprintf(S_PRINT, "[UniVM] Written TIB 0x%08X to FS register\n", TIB);
}

uint32_t map_pe(uc_engine *uc)
{
	IMAGE_DOS_HEADER DOSHeader;
	IMAGE_NT_HEADERS32 PEHeader32;
	IMAGE_SECTION_HEADER PESections;
	ULONG_PTR FileMapVA = GetDebuggedFileBaseAddress();
	size_t totalsize = 0;
	
	DbgMemRead(FileMapVA, (unsigned char *)&DOSHeader, sizeof(IMAGE_DOS_HEADER));
	DbgMemRead(FileMapVA + DOSHeader.e_lfanew, (unsigned char *)&PEHeader32, sizeof(IMAGE_NT_HEADERS32));
	SizeOfImage = PEHeader32.OptionalHeader.SizeOfImage;
	BaseAddress = FileMapVA;

	generic_map(uc, FileMapVA, SizeOfImage);

	mylogprintf(PRINT, "VA 0x%08X", FileMapVA);

	return FileMapVA;
}

static void VM_init()
{
	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if(err)
	{
		mylogprintf(PRINT, "[UniVM] Failed on uc_open() with error returned: %s", uc_strerror(err));
		return;
	}
	
	vm_initialized = true;
	
	VM_exec();
}

static void VM_Stop()
{
	vm_initialized = false;
	uc_close(uc);
}

static void VM_exec()
{
	uc_hook trace1, trace2;
	//const  = *(const SELECTIONDATA *)user_data;
	unsigned int len = 0;
	uint32_t addr = 0;
	unsigned int tr_eax, tr_ebx, tr_ecx, tr_edx, tr_ebp, tr_esp, tr_esi, tr_edi, tr_eip, t_eflags;
	REGDUMP regs;
	char reg_data[10];
	
	if(!vm_initialized)
		return;

loop:
	is_vm_running = false;
	WaitForSingleObject(WaitForStart, INFINITE);
	
	DbgGetRegDump(&regs); // TODO
	
	VM_ctx.regs[EAX] = tr_eax = regs.regcontext.cax;
	VM_ctx.regs[EBX] = tr_ebx = regs.regcontext.cbx;
	VM_ctx.regs[ECX] = tr_ecx = regs.regcontext.ccx;
	VM_ctx.regs[EDX] = tr_edx = regs.regcontext.cdx;
	VM_ctx.regs[EBP] = tr_ebp = regs.regcontext.cbp;
	VM_ctx.regs[ESP] = tr_esp = regs.regcontext.csp;
	VM_ctx.regs[ESI] = tr_esi = regs.regcontext.csi;
	VM_ctx.regs[EDI] = tr_edi = regs.regcontext.cdi;
	VM_ctx.regs[EIP] = tr_eip = regs.regcontext.cip;
	VM_ctx.regs[EFLAGS] = t_eflags = 0;

	if((unsigned int)sel.start != VM_ctx.regs[EIP])
	{
		mylogprintf(PRINT, "[UniVM] You want to execute instructions that don't start at EIP(program counter), this won't be supported yet! Exiting!");
		goto loop;
	}
	
	setupFlagsReg(regs, &VM_ctx.regs[EFLAGS]);
	setupSegmentRegs(uc);	
	
	addr = map_pe(uc);
	
	// map stack early on
	map_stack(uc, VM_ctx.regs[ESP]);	
	
	len = sel.end - sel.start + 1;

	// initialize machine registers
	uc_reg_write(uc, UC_X86_REG_EAX, &VM_ctx.regs[EAX]);
	uc_reg_write(uc, UC_X86_REG_EBX, &VM_ctx.regs[EBX]);
	uc_reg_write(uc, UC_X86_REG_ECX, &VM_ctx.regs[ECX]);
	uc_reg_write(uc, UC_X86_REG_EDX, &VM_ctx.regs[EDX]);
	uc_reg_write(uc, UC_X86_REG_EBP, &VM_ctx.regs[EBP]);
	uc_reg_write(uc, UC_X86_REG_ESP, &VM_ctx.regs[ESP]);	
	uc_reg_write(uc, UC_X86_REG_ESI, &VM_ctx.regs[ESI]);
	uc_reg_write(uc, UC_X86_REG_EDI, &VM_ctx.regs[EDI]);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &VM_ctx.regs[EFLAGS]);
	
	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, (void *)hook_invalid_mem, NULL);
	uc_hook_add(uc, &trace2, UC_HOOK_CODE, (void *)hook_ins, NULL, (uint64_t)1, (uint64_t)0);
	
	is_vm_running = true;
	base = uc;

	// emulate machine code in infinite time
	err = uc_emu_start(uc, sel.start, sel.start + (len), 0, 0);
	if(err)
	{
		uc_reg_read(uc, UC_X86_REG_EIP, &VM_ctx.regs[EIP]);
		mylogprintf(PRINT, "[UniVM] Failed on uc_emu_start() at address 0x%08X with error returned %u: %s", VM_ctx.regs[EIP], err, uc_strerror(err));
		
		goto err;
	}

	uc_reg_read(uc, UC_X86_REG_EAX, &VM_ctx.regs[EAX]);
	uc_reg_read(uc, UC_X86_REG_EBX, &VM_ctx.regs[EBX]);
	uc_reg_read(uc, UC_X86_REG_ECX, &VM_ctx.regs[ECX]);
	uc_reg_read(uc, UC_X86_REG_EDX, &VM_ctx.regs[EDX]);
	uc_reg_read(uc, UC_X86_REG_EBP, &VM_ctx.regs[EBP]);
	uc_reg_read(uc, UC_X86_REG_ESP, &VM_ctx.regs[ESP]);	
	uc_reg_read(uc, UC_X86_REG_ESI, &VM_ctx.regs[ESI]);
	uc_reg_read(uc, UC_X86_REG_EDI, &VM_ctx.regs[EDI]);
	uc_reg_read(uc, UC_X86_REG_EIP, &VM_ctx.regs[EIP]);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &VM_ctx.regs[EFLAGS]);
	
	for(int i = 0; i < 10; i++)
	{
		snprintf(reg_data, sizeof(reg_data) - 1, "%08X", VM_ctx.regs[i]);
		SendMessageTimeout(g_regs[i], WM_SETTEXT, NULL, reg_data, SMTO_NORMAL, 100, NULL);
	}
	
	
	if(vm_stop_req)
		goto err;
	else
		goto loop;
	
/*
	mylogprintf(S_PRINT, "[UniVM] >>> Emulation done. Below is the CPU context\n");
	mylogprintf(S_PRINT, "[UniVM] >>> EAX = 0x%08X %s\n", r_eax, (r_eax == tr_eax ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> EBX = 0x%08X %s\n", r_ebx, (r_ebx == tr_ebx ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> ECX = 0x%08X %s\n", r_ecx, (r_ecx == tr_ecx ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> EDX = 0x%08X %s\n", r_edx, (r_edx == tr_edx ? "" : "(m)"));	
	mylogprintf(S_PRINT, "[UniVM] >>> EBP = 0x%08X %s\n", r_ebp, (r_ebp == tr_ebp ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> ESP = 0x%08X %s\n", r_esp, (r_esp == tr_esp ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> ESI = 0x%08X %s\n", r_esi, (r_esi == tr_esi ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> EDI = 0x%08X %s\n", r_edi, (r_edi == tr_edi ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> EIP = 0x%08X %s\n", r_eip, (r_eip == tr_eip ? "" : "(m)"));
	mylogprintf(S_PRINT, "[UniVM] >>> EFLAGS = 0x%08X %s\n", eflags, (eflags == t_eflags ? "" : "(m)"));	
*/	
	mylogprintf(S_PRINT, "[UniVM] >>> Instructions executed %llu", instructions);
	mylogprintf(FLUSH, NULL);

/*	for(int i = 0; i < mem_map.items; i++)
	{
		mylogprintf(PRINT, "[UniVM] >>> Mem block %08X...%08X", mem_map.mem_block[i].start, mem_map.mem_block[i].end);
	}
*/
err:	
	is_vm_running = false;
	instructions = 0;
	mem_map.items = 0;
	VM_Stop();
	//window?
}

int StartVM()
{
	CreateThread(NULL, 0, VM_init, NULL, 0, NULL);
	
	return 1;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, 
    WPARAM wParam, LPARAM lParam)
{
  switch(msg)  
  {
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }

  return DefWindowProc(hwnd, msg, wParam, lParam);
}

void WindowThread()
{
	MSG msg;
	WNDCLASSEX wclass;
	HWND obj;
	HINSTANCE hInstance = (HINSTANCE)GetModuleHandle("univm.dp32");
	HFONT hFont;
	
	wclass.cbSize = sizeof(WNDCLASSEX);
	wclass.style = 0;
	wclass.lpfnWndProc = WndProc;
	wclass.cbClsExtra = 0;
	wclass.cbWndExtra = 0;
	wclass.hInstance = hInstance;
	wclass.hIcon = LoadIcon(NULL, IDC_ICON);
	wclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wclass.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wclass.lpszMenuName = NULL;
	wclass.lpszClassName = "MainWindowClass";
	wclass.hIconSm = NULL;
	
	if(!RegisterClassEx(&wclass))
	{
		mylogprintf(PRINT, "[UniVM] Cannot register class, reason %d", GetLastError());
		return;
	}
	
	hwnd = CreateWindowEx(WS_EX_OVERLAPPEDWINDOW, wclass.lpszClassName, "UniVM", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 300, 450, GuiGetWindowHandle(), NULL, hInstance, NULL);
	if(!hwnd)
	{
		mylogprintf(PRINT, "[UniVM] Cannot create window, reason %d", GetLastError());
		return;
	}
	
	hFont = CreateFont(12,8,0,0,FW_NORMAL,FALSE,0,FALSE,ANSI_CHARSET,OUT_DEFAULT_PRECIS, 0,CLEARTYPE_QUALITY, FIXED_PITCH | FF_DONTCARE,TEXT("Lucida Console"));
	
	obj = ADDTEXT(EAX:, 10, 23);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[0] = ADDFIELD(47, 20);
	SendMessage(g_regs[0],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(EBX:, 10, 53);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[1] = ADDFIELD(47, 50);
	SendMessage(g_regs[1],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(ECX:, 10, 83);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[2] = ADDFIELD(47, 80);
	SendMessage(g_regs[2],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(EDX:, 10, 113);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[3] = ADDFIELD(47, 110);
	SendMessage(g_regs[3],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(EBP:, 10, 143);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[4] = ADDFIELD(47, 140);
	SendMessage(g_regs[4],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(ESP:, 10, 173);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[5] = ADDFIELD(47, 170);
	SendMessage(g_regs[5],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(ESI:, 10, 203);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[6] = ADDFIELD(47, 200);
	SendMessage(g_regs[6],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(EDI:, 10, 233);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[7] = ADDFIELD(47, 230);
	SendMessage(g_regs[7],WM_SETFONT,(WPARAM)hFont,0);
	
	obj = ADDTEXT(EFL:, 10, 263);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[8] = ADDFIELD(47, 260);
	SendMessage(g_regs[8],WM_SETFONT,(WPARAM)hFont,0);	
	
	obj = ADDTEXT(EIP:, 10, 303);
	SendMessage(obj,WM_SETFONT,(WPARAM)hFont,0);
	g_regs[9] = ADDFIELD(47, 300);
	SendMessage(g_regs[9],WM_SETFONT,(WPARAM)hFont,0);
	

	
	CreateWindowEx(WS_EX_LEFT, "Button", "Stop",
                      WS_VISIBLE | WS_CHILD,
                      90, 330, 45, 28,
                      hwnd,
                      NULL, hInstance, NULL);
	CreateWindowEx(WS_EX_LEFT, "Button", "Start",
                      WS_VISIBLE | WS_CHILD,
                      40, 330, 45, 28,
                      hwnd,
                      NULL, hInstance, NULL);

	
	while(GetMessage(&msg, NULL, 0, 0))
	{
		DispatchMessage(&msg);
	}
	
	if(hwnd != NULL)
		DestroyWindow(hwnd);

	for(int i = 0; i < 10; i++)
	{
		if(g_regs[i])
			DestroyWindow(g_regs[i]);
	}
	
	if(UnregisterClass(wclass.lpszClassName, hInstance) == 0)
		mylogprintf(PRINT, "Cannot unregister class, reason %d", GetLastError());

	CloseHandle(hFont);
	
	ExitThread(0);
}

extern "C" __declspec(dllexport) void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
	if(CreateThread(NULL, 0, WindowThread, NULL, 0, NULL) == NULL)
		mylogprintf(PRINT, "Failed to create GUI thread with error code %d", GetLastError());
		
	WaitForStart = CreateEvent(NULL, FALSE, FALSE, "WaitForStart");
	
	memset(&VM_ctx, 0, sizeof(VM_ctx));
	
	StartVM();
}

extern "C" __declspec(dllexport) void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
	SendMessage(hwnd, WM_DESTROY, 0, 0);
	CloseHandle(WaitForStart);
}

extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch(info->hEntry)
	{
		case MENU_DISASM_VM_EXEC:
		{
			if(!DbgIsDebugging())
			{
				_plugin_logputs("you need to be debugging to use this command");
				break;
			}
			if(!is_vm_running)
			{
				memset(&sel, 0, sizeof(SELECTIONDATA));
				GuiSelectionGet(GUI_DISASSEMBLY, &sel);
				SetEvent(WaitForStart);
			}
			//StartVM(sel);
		}
		case MENU_DISASM_VM_STOP:
		{
			if(!DbgIsDebugging())
			{
				_plugin_logputs("you need to be debugging to use this command");
				break;
			}
			
			if(is_vm_running)
			{
				uc_emu_stop(base);
			}
		}		
		break;
	}
}

extern "C" __declspec(dllexport) void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{

}

void testInit(PLUG_INITSTRUCT* initStruct)
{
}

void testStop()
{
	_plugin_menuclear(hMenuDisasm);
}

void testSetup()
{
	_plugin_menuaddentry(hMenuDisasm, MENU_DISASM_VM_EXEC, "&Execute selected instructions");
	_plugin_menuaddentry(hMenuDisasm, MENU_DISASM_VM_STOP, "&Stop VM Execution");
}
