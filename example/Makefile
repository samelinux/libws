CC=gcc
SRCS=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJS=$(SRCS:.c=.o)
OBJSDIR=obj
LIBWS=libws.a libws.h
OBJSWITHDIR=$(addprefix $(OBJSDIR)/, $(OBJS))
CFLAGS=-lssl -lcrypto -L. -lws -Wall

TARGET=send_receive

.PHONY: all clean

all: $(LIBWS) $(OBJSDIR) $(TARGET)

$(OBJSDIR):
	mkdir -p $(OBJSDIR)

$(LIBWS):
	cp ../libws.a ./
	cp ../libws.h ./

$(TARGET): $(OBJSWITHDIR)
	$(CC) $^ $(CFLAGS) -o $@

$(OBJSDIR)/%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf libws.a
	rm -rf libws.h
	rm -f $(OBJSWITHDIR)
	rm -rf $(OBJSDIR)
	rm -f $(TARGET)

