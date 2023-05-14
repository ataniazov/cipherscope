CC          = gcc 
CFLAGS      = -std=c99 -O3 -mssse3 -msse3 -march=native -Wstrict-aliasing -fstrict-aliasing -Wall -Wextra -pedantic -Waggressive-loop-optimizations -fno-schedule-insns -fomit-frame-pointer
INCLUDES    = -Iinclude -Iaux_include
DEFINES	    = 
SOURCES	    = $(shell find src/ -name '*.c')


build:
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) $(SOURCES) -o misty1.o

run:
	./misty1.o

clean:
	rm -f ./*.o
