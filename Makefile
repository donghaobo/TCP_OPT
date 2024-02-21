SUBDIRS = kmod libxtables
all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:
	for i in $(SUBDIRS); do $(MAKE) -C $$i install || exit 1; done
	depmod -a
