# makefile for aes library for Lua

# change these to reflect your Lua installation
LUA= /usr
LUAINC= $(LUA)/include/lua5.1
LUALIB= $(LUA)/lib
LUABIN= $(LUA)/bin
XYSSL_VERSION=0.9
XYSSL_INC=xyssl-$(XYSSL_VERSION)/include
XYSSL_LIB=xyssl-$(XYSSL_VERSION)/library
XYSSL_FEATURES	= -DHAVE_LONGLONG -DHAVE_RDTSC -DNO_GENPRIME -DNO_MD2 -DNO_MD4 -DNO_DES
MYNAME= lxyssl
# no need to change anything below here
CFLAGS= $(INCS) $(DEFS) $(WARN) -O2 $G -I$(XYSSL_INC) -DXYSSL=$(XYSSL_VERSION)
LDFLAGS= -L$(XYSSL_LIB) 
WARN= #-ansi -pedantic -Wall
INCS= -I$(LUAINC) 

MYLIB= $(MYNAME)
T= $(MYLIB).so
OBJS= $(MYLIB).o
#LIBS= -lxyssl -levent
LIBS= -lxyssl 
CC=gcc


all: so 
	
xyssl: 
	cd xyssl-$(XYSSL_VERSION)/library && make all && cd ../..

o:	$(MYLIB).o

so:	xyssl $T 

$T:	$(OBJS) 
	$(CC) -o $@ -shared $(OBJS) $(LIBS) $(LDFLAGS)
	strip $@

clean:
	cd xyssl-$(XYSSL_VERSION)/library && make clean && cd ../..
	rm -f $(OBJS) $T core core.* a.out 

doc:
	@echo "$(MYNAME) library:"
	@fgrep '/**' $(MYLIB).c | cut -f2 -d/ | tr -d '*' | sort | column

