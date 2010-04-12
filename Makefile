CC=cc -Wall -g

bind-to-tinydns: bind-to-tinydns.c
	${CC} -o bind-to-tinydns bind-to-tinydns.c

clean:
	rm -f bind-to-tinydns
