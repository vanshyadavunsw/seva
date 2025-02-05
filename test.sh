#!/bin/bash

gcc -o test tests/http.c src/http.c src/htable.c lib/murmurhash/murmurhash.c && \
	./test
