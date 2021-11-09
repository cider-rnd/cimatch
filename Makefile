build:
	go build -o bin/cimatch main.go

install:
	cp bin/cimatch /usr/sbin/cimatch

all: build install