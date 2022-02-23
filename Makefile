all = networ-driver programs tests
instructions = nprj0.pdf nprj1.pdf nprj2.pdf nprj3.pdf faq.pdf kickoff-slides.pdf nprjw.pdf
programs = parser hub switch vswitch arp router
tests = test-hub

CFLAGS = -O0 -g # -Wall


network-driver: network-driver.c glab.h
	gcc -g -O0 -Wall -o network-driver network-driver.c

# Try to build instructions, but do not fail hard if this fails:
# The CI doesn't have pdflatex...
$(instructions): %.pdf: %.tex bonus.tex code.tex grading.tex setup.tex testing.tex
	pdflatex $<  || true
	pdflatex $<  || true
	pdflatex $<  || true

clean:
	rm -f network-driver sample-parser $(instructions) *.log *.aux *.out $(programs)

$(programs): %: %.c glab.h loop.c print.c crc.c
	gcc $(CFLAGS) $^ -o $@

test-hub: test-hub.c harness.c harness.h
	gcc $(CFLAGS) $^ -o $@

check: check-hub check-switch check-arp check-router

check-hub: test-hub
	./test-hub ./hub
check-switch: test-switch
	./test-switch ./switch
check-vswitch: test-vswitch
	./test-vswitch ./vswitch
check-arp: test-arp
	./test-arp ./arp
check-router: test-router
	./test-router ./router
arch.pdf: arch.svg
	rsvg-convert -f pdf -o arch.pdf arch.svg

.PHONY: clean check check-hub check-switch check-arp check-router
