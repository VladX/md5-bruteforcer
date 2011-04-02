CC= gcc
PARAMS= -O3 -static -lpthread
NVCC= nvcc
NVCCPARAMS= -lpthread

all:
	$(CC) ./brute.c -c -o ./brute.o $(PARAMS)
	$(NVCC) ./gpu.cu -c -o ./gpu.o $(NVCCPARAMS)
	$(NVCC) ./*.o -o ./brute $(NVCCPARAMS)
brute: brute.o
	$(CC) ./brute.o -o ./brute $(PARAMS)
brute.o:
	$(CC) ./brute.c -c -o ./brute.o $(PARAMS)
clean:
	rm -f ./*.o
	rm -f ./brute
