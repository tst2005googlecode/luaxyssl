# makefile for aes library for Lua

# change these to reflect your Lua installation
LUA= /usr/local
LUAINC= $(LUA)/include
LUALIB= $(LUA)/lib
LUABIN= $(LUA)/bin
XYSSL_INC=/home/colinux/xyssl-0.7/include
XYSSL_LIB=/home/colinux/xyssl-0.7/library
XYSSL_FEATURES	= -DHAVE_SSE2 -DHAVE_LONGLONG -DHAVE_RDTSC -DNO_GENPRIME -DNO_MD2 -DNO_MD4 -DNO_DES
MYNAME= lxyssl
# no need to change anything below here
CFLAGS= $(INCS) $(DEFS) $(WARN) -O2 $G -I$(XYSSL_INC)
LDFLAGS= -L$(XYSSL_LIB)
WARN= #-ansi -pedantic -Wall
INCS= -I$(LUAINC) 

MYLIB= $(MYNAME)
T= $(MYLIB).so
OBJS= $(MYLIB).o
LIBS= -lxyssl
CC=gcc

all:	so

o:	$(MYLIB).o

so:	$T

$T:	$(OBJS) 
	$(CC) -o $@ -shared $(OBJS) $(LIBS) $(LDFLAGS)
	strip $@

clean:
	rm -f $(OBJS) $T core core.* a.out 

doc:
	@echo "$(MYNAME) library:"
	@fgrep '/**' $(MYLIB).c | cut -f2 -d/ | tr -d '*' | sort | column

