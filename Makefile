CC=gcc
GLIB=`pkg-config --libs --cflags glib-2.0`
OPENSSL=`pkg-config --libs --cflags openssl`
NIDS=-lnids

all: extract_images

extract_images: extract_images.c
	$(CC) $(CFLAGS) $(NIDS) $(GLIB) $(OPENSSL) -Wall -Werror -D_GNU_SOURCE -o $@ $^

clean:
	@rm -vf extract_images out/index.html
	@find out/ -maxdepth 1 -type f -name "*.jpg" -exec rm -v '{}' ';'
	@find out/ -maxdepth 1 -type f -name "*.png" -exec rm -v '{}' ';'
