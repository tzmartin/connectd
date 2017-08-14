CFLAGS=-g
export CFLAGS

connect: *.go
	go build -i -o dist/connectd
	cp README.md dist/README.md
	rm -rf dist/.DS_Store
	tar -zcvf connectd.tar.gz dist

.PHONY: buildlinux
linux:
	GOOS=linux GOARCH=amd64 go build -o dist/connectd
	cp README.md dist/README.md
	rm -rf dist/.DS_Store
	tar -zcvf releases/connectd.$(version)-linux.tar.gz dist

.PHONY: buildmac
darwin:
	GOOS=darwin GOARCH=amd64 go build -o dist/connectd
	rm -rf dist/.DS_Store
	tar -zcvf releases/connectd.$(version)-darwin.tar.gz dist

.PHONY: clean
clean:
	rm -rf dist