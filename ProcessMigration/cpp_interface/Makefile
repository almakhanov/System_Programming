all: ck.x restart.x dump.x

ch.x: ck.cpp
	g++ ck.cpp -o ck.x

restart.x: restart.cpp
	g++ restart.cpp -o restart.x

dump.x: dump.cpp
	g++ dump.cpp -o dump.x

clean:
	rm -f *.x *.o
