programs = parser hub switch vswitch arp router
#tests = test-hub
#tests =  test-switch
#tests = test-vswitch
#tests = test-arp
tests = test-router

all: network-driver $(programs) $(tests)


CFLAGS = -O0 -g # -Wall


network-driver: network-driver.c glab.h
	gcc -g -O0 -Wall -o network-driver network-driver.c

clean:
	rm -f network-driver sample-parser *.log *.aux *.out $(programs)

$(programs): %: %.c glab.h loop.c print.c crc.c
	gcc $(CFLAGS) $^ -o $@

#test-hub: test-hub.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
#test-switch: test-switch.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
#test-vswitch: test-vswitch.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
#test-arp: test-arp.c harness.c harness.h
#	gcc $(CFLAGS) $^ -o $@
test-router: test-router.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@

#check: check-hub
#check: check-switch
#check: check-arp
check: check-router

#check-hub: test-hub
#	./test-hub ./hub
#check-switch: test-switch
#	./test-switch ./switch
#check-vswitch: test-vswitch
#	./test-vswitch ./vswitch
#check-arp: test-arp
#	./test-arp ./arp
check-router: test-router
	./test-router ./router
arch.pdf: arch.svg
	rsvg-convert -f pdf -o arch.pdf arch.svg

.PHONY: clean check check-hub check-switch check-arp check-router
