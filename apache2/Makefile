
APXS=apxs2
APACHECTL=apache2ctl

all:
	$(APXS) -c mod_scgi.c

# XXX should not need the -c option but for some reason it's required :-(
install:
	$(APXS) -i -c mod_scgi.c

clean:
	rm -rf mod_scgi.o mod_scgi.lo mod_scgi.slo mod_scgi.la .libs

start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
