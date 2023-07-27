export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = xdp_slb

all: generate $(OBJ)

$(OBJ):
	go mod tidy && go build -gcflags "-N -l" -o ${OBJ} ./

generate: xdp_bpfel.o
xdp_bpfel.o: ebpf/xdp.c
	go generate

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find . -path ./vendor -prune -o -name '*.go' -print | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps
