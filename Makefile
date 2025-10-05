.PHONY: test-musl-static test-musl-dyn test-glibc-static test-glibc-dyn

MUSLGCC=/usr/local/musl/bin/musl-gcc

test-musl-static: test.c
	$(MUSLGCC) -o test -static -static-pie -g $<

test-musl-dyn: test.c
	$(MUSLGCC) -o test -fPIE -fPIC -g $<

test-glibc-static: test.c
	gcc -o test -static-pie -g $<

test-glibc-dyn: test.c
	gcc -o test -fPIE -fPIC -g $<
