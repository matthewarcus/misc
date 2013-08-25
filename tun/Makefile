all: reflect

reflect: reflect.cpp
	g++ -W -Wall -O3 reflect.cpp -o reflect -lcap
	sudo setcap cap_net_admin+ep ./reflect

clean:
	rm -f reflect
