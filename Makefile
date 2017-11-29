CFLAGS=-g
export CFLAGS

connect: *.go
	go build -i -o build/connectd
	cp README.md dist/README.md
	rm -rf build/.DS_Store
	tar -zcvf connectd.tar.gz build

.PHONY: buildlinux
linux:
	@GOOS=linux GOARCH=amd64 go build -o build/connectd
	@cp README.md build/README.md
	@rm -rf build/.DS_Store
	@tar -zcvf releases/connectd.$(version)-linux.tar.gz build
	echo Done

.PHONY: buildmac
darwin:
	@GOOS=darwin GOARCH=amd64 go build -o build/connectd
	@rm -rf build/.DS_Store
	@tar -zcvf releases/connectd.$(version)-darwin.tar.gz build
	@echo Done

.PHONY: clean
clean:
	@rm -rf build