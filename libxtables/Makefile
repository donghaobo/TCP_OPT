CFLAGS=-I../kmod/ -fPIC
LDFLAGS=-lxtables -shared
all: lib

lib: libxt_TCPOPTADD.so

%.so: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f libxt_TCPOPTADD.so

install: lib
	install -m 755 libxt_TCPOPTADD.so /lib64/xtables/
