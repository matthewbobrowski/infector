OBJECT_FILES = tracee tracer parasite library.so.1.0 library.o parasite.o

all: library.so.1.0 tracee tracer parasite

library.so.1.0: library.o
	ld -shared -o library.so.1.0 library.o
library.o: library.c
	gcc -fPIC -nostdlib -c library.c
parasite: parasite.o
	ld -o parasite parasite.o
parasite.o: parasite.asm
	nasm -f elf64 parasite.asm
tracer: tracer.c
	gcc -o tracer tracer.c
tracee: tracee.c
	gcc -o tracee tracee.c
.PHONY: clean
clean:
	rm $(OBJECT_FILES)
