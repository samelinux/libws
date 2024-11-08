CC=gcc
SRCS=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJS=$(SRCS:.c=.o)
OBJSDIR=obj
OBJSWITHDIR=$(addprefix $(OBJSDIR)/, $(OBJS))
CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic
LFLAGS=-lssl -lcrypto
AR=ar
ARFLAGS=rcs
TARGET=libws.a

.PHONY: clean

all: $(OBJSDIR) $(TARGET)

$(OBJSDIR):
	mkdir -p $(OBJSDIR)

$(OBJSDIR)/%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@ $(LFLAGS)

$(TARGET): $(OBJSWITHDIR)
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -rf $(OBJSDIR)
	rm -f $(TARGET)

