#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unicorn/unicorn.h>

#include "pluginsdk\bridgemain.h"
#include "pluginsdk\TitanEngine\TitanEngine.h"
#include "univm.h"
#include "memory.h"
#define LODWORD(_qw)    ((DWORD)(_qw))

int generic_map(uc_engine *uc, uint64_t address, size_t size, bool copyfrom_host=true, enum uc_prot prot=UC_PROT_ALL)
{
	uint64_t address_align = align_address(address);
	size_t size_align = align_size(size), overlap = 0;
	unsigned char *data;
	unsigned int i = mem_map.items;
	uc_err err;

	for(unsigned int k = 0; k < i; k++)
	{
		if((LODWORD(address_align)+size_align) >= mem_map.mem_block[k].start && (LODWORD(address_align)+size_align) <= mem_map.mem_block[k].end)
		{
			overlap = (LODWORD(address_align)+size_align) - mem_map.mem_block[k].start;
			if(overlap == 0 && (LODWORD(address_align)+size_align) > mem_map.mem_block[k].start)
				return 1;
				
			mylogprintf(PRINT, "Overlaps with %d!\n", overlap); // debug
		}
	}
	
	err = uc_mem_map(uc, address_align, size_align, prot);
	if(err != UC_ERR_OK)
	{
		mylogprintf(PRINT, "[UniVM] Failed to map memory at address 0x%016X(size %Iu) with error: %s\n", address_align, size_align, uc_strerror(err));
		return -1;
	}
	
	if(copyfrom_host)
	{
		data = new unsigned char[size_align]();
	
		if(!DbgMemRead(LODWORD(address_align), data, size_align-overlap))
		{
			if(GetLastError() != 299)
			{
				if(!DbgMemRead(LODWORD(address_align), data, LODWORD(address_align) < TIB ? PAGE_4K : 0x30))
				{
					mylogprintf(PRINT, "[UniVM] Failed to DbgMemRead at UC_MEM_WRITE_UNMAPPED of 0x%08X with error code %d", LODWORD(address_align), GetLastError());
					delete[] data;
					return -1;
				}
			}
		
			//mylogprintf(PRINT, "[UniVM] WARNING: DbgMemRead only did a partial copy of memory at address 0x%08X(size %lu) with error code %d. This is not fatal.", LODWORD(address_align), size_align, GetLastError());
		}
			
		err = uc_mem_write(uc, address_align, data, size_align-overlap);
		if(err != UC_ERR_OK)
		{
			delete[] data;
			mylogprintf(PRINT, "[UniVM] Failed to write data, %s(sz %d)\n", uc_strerror(err), size_align-overlap);
			return -1;
		}	
	
		delete[] data;
	}
	
	//must make mem_map dynamic and check that `i` isn't bigger than the size of mem_block
	mem_map.mem_block[i].start = address_align;
	mem_map.mem_block[i].end = address_align + size_align;
	mem_map.mem_block[i].size = size_align;
	mem_map.mem_block[i].req = size;
	mem_map.items++;	
	
	return 1;
}

int mem_unmap(uc_engine *uc, uint64_t address, size_t size)
{
	uint64_t address_align = align_address(address);
	size_t size_align = align_size(size);
	uc_err err;
}

int map_stack(uc_engine *uc, addr_t address)
{
	int err;
	uint32_t stkbase = GetStackBase();
	uint32_t stklimit = GetStackLimit();
	uint32_t base_align = align_address(stkbase);
	size_t size = stkbase - stklimit;
	size_t size_align = align_size(size);
	
	if(stkbase != base_align)
	{
		
	}
	
	mylogprintf(PRINT, "[UniVM] Early mapping of stack %08X-%08X(aligned to %08X). %u bytes will be mapped and %08X.",stklimit, stkbase, base_align, size_align, base_align - size_align);
	
	err = generic_map(uc, base_align - size_align , size_align);
	if(!err)
		mylogprintf(PRINT, "[UniVM] Failed to map stack. ");
	//err = generic_map(uc, align_address(address), PAGE_8K * 4);
	
	return err;
}

void hook_ins(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	instructions++;
	unsigned char buf[256];
	//uint32_t callLoc = 0;
	uint32_t addr32 = (uint32_t)(address & 0xFFFFFFFF);
	//static bool canrun = false;
	if(address < BaseAddress || address > (BaseAddress+SizeOfImage))
	{
		dump_state(uc);
		uc_emu_stop(uc);
	}
	/*if(!canrun)
	{
		if(addr32 == 0x3700107C)
		{
			canrun = true;
		}
		else
			return;
	}*/
	//dump_state(uc);
	/*
	if(uc_mem_read(uc, address, buf, size) != UC_ERR_OK)
	{
		mylogprintf(PRINT, "not ok - uc_mem_read fail during hook_code callback");
		
		if(uc_emu_stop(uc) != UC_ERR_OK)
		{
			mylogprintf(PRINT, "not ok - uc_emu_stop fail during hook_code callback");
		}
	}*/
/*
    switch(buf[0]) {
        case 0xe8:  // inc ecx
			memcpy(&callLoc, buf+1, 4);
			//mylogprintf(PRINT, "[UniVM] CALL to %08X, %08X", (addr32+size)+callLoc, addr32);
			//uc_emu_stop(uc);
            break;
        default:  // all others
            break;
    }*/
}
		
bool hook_mem_rw(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	uc_err err;
	uint32_t address_align = PAGE_ALIGN(address, PAGE_4K);
	uint32_t EIP;

	unsigned char *data = NULL;
	
	if(address == 0)
	{
		mylogprintf(PRINT, "[UniVM] Attempting to access address 0x0. Exiting!\n");
		return false;
	}

	uc_reg_read(uc, UC_X86_REG_EIP, &EIP);
	switch(type)
	{
		default:
			return false;
		break;
		case UC_MEM_WRITE:
			mylogprintf(PRINT, "[UniVM] Hooked write to address %08llX with value %08llX at EIP %08X", address, value, EIP);
			
			return true;
		break;
		case UC_MEM_READ:
			mylogprintf(PRINT, "[UniVM] Hooked read from address %08llX at EIP %08X", address, EIP);
			
			return true;
		break;	
	}
}

bool hook_invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	uc_err err;
	uint32_t address_align = PAGE_ALIGN(address, PAGE_4K);
	uint32_t EIP;

	unsigned char *data = NULL;
	
	if(address == 0)
	{
		mylogprintf(PRINT, "[UniVM] Attempting to access address 0x0. Exiting!\n");
		return false;
	}

	uc_reg_read(uc, UC_X86_REG_EIP, &EIP);
	switch(type)
	{
		default:
			return false;
		break;
		case UC_MEM_WRITE_UNMAPPED:
		// there could be data here that needs to change byte by byte so need to copy it 
			mylogprintf(PRINT, "[UniVM] Mapping write address 0x%08llX to aligned 0x%08X at EIP %08X", address, address_align, EIP);

			if(!generic_map(uc, address, PAGE_8K))
			{
				mylogprintf(PRINT, "[UniVM] Failed to map write address");
				return false;
			}
			
			return true;
		break;
		case UC_MEM_READ_UNMAPPED:
			mylogprintf(PRINT, "[UniVM] Mapping read address 0x%08llX to aligned 0x%08X at EIP %08X", address, address_align, EIP);
			
			if(!generic_map(uc, address, PAGE_8K))
			{
				mylogprintf(PRINT, "[UniVM] Failed to map read address");
				return false;
			}
			
			return true;
		break;		
	}
}

inline uint32_t align_address(uint64_t address)
{
	return (uint32_t)PAGE_ALIGN((uint32_t)address, PAGE_4K);
}

inline size_t align_size(size_t size)
{
	return PAGE_PREPARE(size, PAGE_8K);
}

