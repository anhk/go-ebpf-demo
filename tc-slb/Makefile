export GOPROXY=https://goproxy.cn,direct
export GO111MODULE=on

OBJ = tc-slb

all: generate $(OBJ)

$(OBJ):
	go mod tidy && go build -gcflags "-N -l" -o ${OBJ} ./

generate: ebpf_bpfel.o
ebpf_bpfel.o: ebpf/tc-slb.c
	go generate

clean:
	rm -fr $(OBJ)

-include .deps
dep:
	echo -n "$(OBJ):" > .deps
	find . -path ./vendor -prune -o -name '*.go' -print | awk '{print $$0 " \\"}' >> .deps
	echo "" >> .deps
