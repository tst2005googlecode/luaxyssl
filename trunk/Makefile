# makefile for lxyssl library for Lua

# change these to reflect your Lua installation
LUA= /usr
LUA_INSTALL_LIBDIR=/usr/local/lib/lua/5.1
LUA_INSTALL_DIR=/usr/local/share/lua/5.1
LUAINC= $(LUA)/include/lua5.1
LUALIB= $(LUA)/lib
LUABIN= $(LUA)/bin
XYSSL_VERSION=9
XYSSL_INC=xyssl-0.$(XYSSL_VERSION)/include
XYSSL_LIB=xyssl-0.$(XYSSL_VERSION)/library
XYSSL_DEBUG= -DXYSSL_DEBUG_MSG -DXYSSL_DEBUG_C
XYSSL_FEATURES= -DXYSSL_HAVE_LONGLONG -DXYSSL_HAVE_RDTSC -DNO_GENPRIME -DNO_MD2 -DNO_MD4 -DXYSSL_HAVE_SSE2 
#XYSSL_FEATURES= -DXYSSL_HAVE_LONGLONG -DXYSSL_HAVE_RDTSC -DNO_GENPRIME -DNO_MD2 -DNO_MD4 -DXYSSL_HAVE_SSE2 $(XYSSL_DEBUG)
MYNAME= lxyssl
# no need to change anything below here
CFLAGS= $(INCS) $(DEFS) $(WARN) -O2 $G -I$(XYSSL_INC) -DXYSSL=$(XYSSL_VERSION) $(XYSSL_FEATURES)
LDFLAGS= -L$(XYSSL_LIB) 
WARN= #-ansi -pedantic -Wall
INCS= -I$(LUAINC) 

MYLIB= $(MYNAME)
T= $(MYLIB).so
OBJS= $(MYLIB).o
#LIBS= -lxyssl -levent
LIBS= -lxyssl -llua5.1
CC=gcc
LUA_MODULES=bufferio.lua ssl.lua security.lua

all: so 
	
$(XYSSL_LIB)/libxyssl.a: 
	cd xyssl-0.$(XYSSL_VERSION)/library && make all XYSSL_CFLAGS="$(XYSSL_FEATURES)" && cd ../..

o:	$(MYLIB).o

so:	$T 

$T:	$(OBJS) $(XYSSL_LIB)/libxyssl.a
	$(CC) -o $@ -shared $(OBJS) $(LIBS) $(LDFLAGS)
	strip $@

clean:
	cd xyssl-0.$(XYSSL_VERSION)/library && make clean && cd ../..
	rm -f $(OBJS) $T core core.* a.out 

install: $T
	install lua/* $(LUA_INSTALL_DIR)/
	install $(T) $(LUA_INSTALL_LIBDIR)/

doc:
	@echo "$(MYNAME) library:"
	@fgrep '/**' $(MYLIB).c | cut -f2 -d/ | tr -d '*' | sort | column

