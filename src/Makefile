CC = /usr/bin/cc

CFLAGS		= -Iheaders -Wall -g -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer 
CLIBFLAGS	= -Iheaders -std=c99 -pedantic -Wall -Wextra -g -fPIC
GTKINCLUDE	= -pthread -I/usr/include/gtk-3.0 -I/usr/lib64/gtk-3.0/include -I/usr/include/atk-1.0 -I/usr/include/cairo -I/usr/include/pango-1.0 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/lib64/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/freetype2 -I/usr/include/libpng12 -I/usr/include/harfbuzz -I/usr/include/gdk-pixbuf-2.0
GTKLIB		= -lgtk-3 -lgdk-3 -latk-1.0 -lgio-2.0 -lpangoft2-1.0 -lgdk_pixbuf-2.0 -lpangocairo-1.0 -lcairo -lpango-1.0 -lfreetype -lfontconfig -lgobject-2.0 -lgmodule-2.0 -lgthread-2.0 -lrt -lglib-2.0 -lpolynomial -lm
INCLUDE		= -I/usr/local/include -I/usr/local/include/openssl -I/usr/local/lib -lssl -lcrypto

SOURCES = 	$(wildcard ./c_files/*.c)
HEADERS = 	$(wildcard ./headers/*.h)

OBJS = $(SOURCES: .c=.o)

all: clean GUI main_test

GUI: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) $(GTKINCLUDE) $(INCLUDE) GUI.c $(GTKLIB) -o $@

main_test: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) $(GTKINCLUDE) $(INCLUDE) main_test.c $(GTKLIB) -o $@


.PHONY: clean

clean:
	rm -f GUI
	rm -f main_test
	rm -rf *.o