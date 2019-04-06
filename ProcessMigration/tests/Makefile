all: res.x ck.x testfile

testfile:
	touch testfile

res.x: res.c
	gcc res.c -o res.x

ck.x: ck.c
	gcc ck.c -o ck.x

clean:
	rm -f *.x testfile
