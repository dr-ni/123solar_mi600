all: deye-logger

deye-logger: deye-logger.o
	g++ -Wall -o deye-logger deye-logger.o -lpthread

deye-logger.o: deye-logger.c
	g++ -Wall -Wno-psabi -c deye-logger.c

clean:
	rm -f ./deye-logger.o ./deye-logger

install:
	cp -f ./deye-logger /usr/bin/deye-logger
	
