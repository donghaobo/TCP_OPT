obj-m += xt_TCPOPTADD.o

ifeq ($(KERNDIR), )
KDIR := /lib/modules/$(shell uname -r)/build
else
KDIR := $(KERNDIR)
endif

ifeq ($(INSDIR), )
INSDIR := /lib/modules/$(shell uname -r)/extra
endif
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) modules clean

install:
	if [ -d "$(INSDIR)" ]; then \
		install -m 664 xt_TCPOPTADD.ko $(INSDIR)/xt_TCPOPTADD.ko; \
	fi
