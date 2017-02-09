CC=gcc
CFLAGS=-Wall -Wextra -Wmissing-declarations

TARGET=dump.dylib
HEADERS=shn.h pcap.h
OBJECTS=dump.o shn.o pcap.o iosshn.o

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -ldl -dynamiclib -o $@ $^

%.o: %.c $(HEADERS) 
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f $(TARGET) $(OBJECTS)
