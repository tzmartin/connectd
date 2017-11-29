package main

import (
	"testing"
)

func upload(t *testing.T) {
	/* this is a comment style*/
	w := client.Bucket("sai-corp-dev-session-ingest").Object("obj").NewWriter(ctx)
	w.Resumable = true
	_, err := w.Write([]byte("hello world"))
	t.Log("I  can print a special message")
}
