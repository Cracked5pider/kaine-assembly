MAKEFLAGS += "-j 16"

##
## Project Name
##
NAME := "assembly"

##
## Compilers and linkers
##
CC_X64 := x86_64-w64-mingw32
CC_X86 := i686-w64-mingw32

##
## source code
##
PIC_SRC := $(wildcard src-core/*.cc)
PIC_OBJ := $(PIC_SRC:%.cc=%.o)

##
## Compiler flags
##
PIC_CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib
PIC_CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
PIC_CFLAGS += -s -ffunction-sections -falign-jumps=1 -w
PIC_CFLAGS += -falign-labels=1 -fPIC -Wl,-Tscripts/linker-section.ld
PIC_CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup
PIC_CFLAGS += -Iinclude -masm=intel -fpermissive -mrdrnd

all:
	@ make x64-core
	@ make x64-bof

x64-bof:
	@ $(CC_X64)-gcc src-obj/Main.c -c -o bin/assembly.x64.obj -Os -s -Qn

x64-core: x64-asm $(PIC_OBJ)
	@ $(CC_X64)-g++ bin/obj-core/*.x64.o -o bin/$(NAME)-core.x64.exe $(PIC_CFLAGS)
	@ python3 scripts/extract.py -f bin/$(NAME)-core.x64.exe -o bin/$(NAME)-core.x64.bin
	@ xxd -i bin/$(NAME)-core.x64.bin > src-obj/ScAssemblyEnter.h
	@ echo -e "__attribute__( ( section( \".text\" ) ) )\n$$(cat src-obj/ScAssemblyEnter.h)" > src-obj/ScAssemblyEnter.h
	@ sed -i 's\bin_assembly_core_x64\core_stub\g' src-obj/ScAssemblyEnter.h
	@ rm bin/$(NAME)-core.x64.exe

x64-asm:
	@ nasm -f win64 src-core/asm/AdjustStack.x64.asm -o bin/obj-core/AdjustStack.x64.o

$(PIC_OBJ):
	@ echo compiling $(basename $@).cc ==> bin/obj-core/$(NAME)_$(basename $(notdir $@)).x64.o
	@ $(CC_X64)-g++ -o bin/obj-core/$(NAME)_$(basename $(notdir $@)).x64.o -c $(basename $@).cc $(PIC_CFLAGS)

clean:
	@ rm -rf bin/obj-bof/*.o*
	@ rm -rf bin/obj-core/*.o*
	@ rm -rf bin/dotnet-*
