
include ../options.mak

.PHONY: all clean check

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS) -I../include

LIBRARY = libmantis.a

OBJS = \
	skinny-internal.o \
	mantis-cipher.o \
	mantis-ctr.o \
	mantis-ctr-vec128.o \
	mantis-parallel.o \
	mantis-parallel-vec128.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

# Plain C core source files.
mantis-cipher.o: ../include/mantis-cipher.h skinny-internal.h
mantis-ctr.o: ../include/mantis-cipher.h skinny-internal.h \
                    mantis-ctr-internal.h
mantis-parallel.o: ../include/mantis-cipher.h ../include/mantis-parallel.h \
                   skinny-internal.h

# Source files that use 128-bit SIMD vector instructions.
mantis-ctr-vec128.o: mantis-ctr-vec128.c ../include/mantis-cipher.h \
                    skinny-internal.h mantis-ctr-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

mantis-parallel-vec128.o: mantis-parallel-vec128.c ../include/mantis-cipher.h \
                    skinny-internal.h ../include/mantis-parallel.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<
