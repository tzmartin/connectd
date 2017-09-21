# connectd

[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> A service for managing communication flow patterns, data processing and visualization

## Todo

- spawn only one session of connectd?  Or should we allow multiple instances?

## Latest Release: 0.0.5

**Release Notes: 0.0.5** - September 21, 2017

- websocket server port ::5555/data

**Release Notes: 0.0.4** - September 21, 2017

- Added IPC events according to [IPC Specification](https://docs.google.com/document/d/1XOiNHH9BwMXb0EZpWmK3kljaMJnmunjiiR692iOUg6w/edit)
- Added staging, completed dir flags
- Added http client for GCS uploads to `session-ingest` bucket
- Added md5 hash validation for uploads
- Added http trace for monitoring lifecycle
- Added concurrency and parralel uploading

**Release Notes** - August 11, 2017

- Initial release
- This release exposes a pub/sub scheme using unix named pipes. 
- The interface is designed to test IPC flow between Connect and Capture Kiosk using a schemeless message structure using a serialized JSON string using Unicode characters, wrapped in double quotes, using backslash escapes.

Binaries:

- linux (amd64)
- darwin (amd64)

## Table of Contents

- [Functional Requirements](#)
- [Background](#background)
- [Install](#install)
- [Build](#build)
- [Usage](#usage)
- [API](#api)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Functional Requirements

- Should receive command line flags (non positional arguments): pipe, string
- Should receive and parse URI scheme requests as URL parameters
- Should receive a string from a given named pipe (fifo)
- Should send a string to a given named pipe (fifo)
- Should register URI protocol (pipe://) that's accessible from a Chrome browser
- Should be executable on linux (amd64): `GOOS=linux GOARCH=amd64 go build main.go`

## Security

## Background

## Install

Requires go version > 1.3. Tested 1.8.3 (darwin/amd64). [Installation instructions](https://golang.org/doc/install)

**Dependencies**

```
go get github.com/Sirupsen/logrus
go get github.com/tzmartin/namedpiper
go get -u cloud.google.com/go/storage

```

## Build

Run `make`.

```
make darwin version=0.0.1
make linux version=0.0.1

// Output
releases/connectd.0.0.1-linux.tar.gz
```

**Releases** 

Releases are available in `/releases` folder. 

To update a release:

1. Update this README with latest version
2. Build with version flag
3. Tag the repo with version

Tag a release using [semantic versioning](http://semver.org/).

```
git tag 0.0.0
git push origin <tag>
```

BitBucket does not support binary file attachments as a release feature (ie, Github).  There is soft limit to 1GB and an hard limit to 2GB.

For binary or executable storage, the recommendation is host the release binary on a CDN (ie, Google Cloud Storage).

## Usage

```
// Ensure binary is executable
chmodx connectd
```

```
// Subscribe to a channel
./connectd -sub=hooli

// Publish to a channel
./connectd -pub=hooli -message="{\"foo\":\"bar\"}"
```

## API

```
Usage of ./connectd:
  -dir string
    	FIFO directory absolute path (default "/tmp/pipes")
  -message string
    	JSON encoded string (default "{\"foo\":\"bar\"}")
  -pub string
    	Publish to unix named pipe (fifo)
  -sub string
    	Subscribe to unix named pipe (fifo)
```

## Maintainers

[@tzmartin](https://github.com/tzmartin)
[@sophrinix](https://github.com/sophrinix)

## Contribute

Small note: If editing the README, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

Commercial © 2017 Scientific Analytics, Inc.
