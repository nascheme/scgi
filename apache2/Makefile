
APXS=apxs2
APACHECTL=apache2ctl

# Extra args for building a multi-architecture version OS X 10.5.
UNIVERSAL="-arch ppc7400 -arch ppc64 -arch i386 -arch x86_64"

all:
	$(APXS) -c mod_scgi.c

install:
	$(APXS) -i -c mod_scgi.c

universal:
	$(APXS) -c -Wl,$(UNIVERSAL) -Wc,$(UNIVERSAL) mod_scgi.c

install_universal:
	$(APXS) -c -Wl,$(UNIVERSAL) -Wc,$(UNIVERSAL) mod_scgi.c

clean:
	rm -rf mod_scgi.o mod_scgi.lo mod_scgi.slo mod_scgi.la .libs

start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
