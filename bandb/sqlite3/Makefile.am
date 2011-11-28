

SOURCES = sqlite3.c
bin_PROGRAMS = ratbox-sqlite3
AM_CFLAGS = -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION=1
ratbox_sqlite3_SOURCES = shell.c
ratbox_sqlite3_LDADD = libsqlite3.a


.c.lo:
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(AM_CFLAGS) -prefer-pic -I../include -I. -c $< -o $@ 

S_OBJS= $(SOURCES:.c=.lo)

	

libsqlite3.a: $(S_OBJS)
	$(LIBTOOL) --mode=link $(CC) -all-static -o libsqlite3.a $(S_OBJS)

all: libsqlite3.a
