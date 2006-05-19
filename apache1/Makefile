all: mod_scgi.so

mod_scgi.so: mod_scgi.c
	apxs -c $<

clean:
	rm -f mod_scgi.so mod_scgi.o

install:
	install -m 0755 -d $(DESTDIR)/usr/lib/apache/1.3/
	install -m 0755 mod_scgi.so $(DESTDIR)/usr/lib/apache/1.3/
