#!/bin/bash

gcc -o test tests/http.c src/http.c src/htable.c lib/murmurhash/murmurhash.c && \
	./test

gcc -o test tests/htable.c src/htable.c lib/murmurhash/murmurhash.c && \
	./test
