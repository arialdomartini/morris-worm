C_FILES = worm.c net.c hs.c cracksome.c stubs.c
H_FILES = worm.h

OFILES = worm.o net.o hs.o cracksome.o stubs.o

# Luckily, the original used no optimization
CFLAGS =
# Most sites will have to remove the "-D" -- send for our souped-up version
# of ctags becker@trantor.harris-atd.com

TAGS_FLAGS = -xDt

test: $(OFILES)
	$(CC) -o test $(OFILES)
$(OFILES): worm.h

clean:
	rm -f *.o *~ *.bak
tags:
	ctags -xDt > tags
tar:
	tar -cf foo.tar  description Makefile $(C_FILES) $(H_FILES) x8113550.c
