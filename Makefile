LIBS = -libverbs -lrdmacm

device_fork_query: main.cpp
	g++ $^  $(LIBS) -o $@

main.cpp: device.h
	touch $@

clean:
	rm -rf device_fork_query
