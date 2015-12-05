#ifndef _MEMORY_H
#define _MEMORY_H

#define PAGE_8K (1 << 13)
#define PAGE_4K (1 << 12)
#define PAGE_MASK(page) ~(page - 1)
#define PAGE_PREPARE(addr,page) (((addr) + page - 1) & PAGE_MASK(page))
#define PAGE_ALIGN(addr,page) (addr - (PAGE_PREPARE(addr,page) - addr) & PAGE_MASK(page))
#define HIDWORD(l) ((uint32_t)(l & 0xFFFFFFFF))
#define SETBIT(buf, bit) (buf |= 1 << bit)
#define CLRBIT(buf, bit) (buf &= ~(1 << bit))

void hook_ins(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
bool hook_invalid_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
int generic_map(uc_engine *uc, uint64_t address, size_t size, bool copyfrom_host=true, enum uc_prot prot=UC_PROT_ALL);
int map_stack(uc_engine *uc, uint32_t address);
size_t align_size(size_t);
uint32_t align_address(uint64_t address);

#endif // _MEMORY_H
