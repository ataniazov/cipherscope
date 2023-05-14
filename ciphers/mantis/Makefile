
.PHONY: all clean check perf

all:
	(cd src; $(MAKE) all)
	(cd test; $(MAKE) all)

clean:
	(cd src; $(MAKE) clean)
	(cd test; $(MAKE) clean)

check:
	(cd src; $(MAKE) check)
	(cd test; $(MAKE) check)

perf:
	(cd src; $(MAKE) all)
	(cd test; $(MAKE) perf)
