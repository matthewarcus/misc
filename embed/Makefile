# Override on command line eg. with 'make PYVERSION=3.8'
PYVERSION = 3.7

ALL = embed

all: $(ALL)

embed: embed.o
	g++ $^ $$(/usr/bin/python${PYVERSION}-config --ldflags) -o $@

embed.o: embed.cpp
	g++ -g -c -fPIE -Wall -g $$(/usr/bin/python${PYVERSION}-config --cflags) $< -o $@

clean:
	rm -f $(ALL) *.o

.PHONY: all clean
