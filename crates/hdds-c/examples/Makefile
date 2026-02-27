# Makefile for HDDS C FFI Examples

CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -L../../../target/debug -lhdds_c -lpthread -ldl -lm
INCLUDES = -I..

# Targets
all: basic_pubsub

basic_pubsub: basic_pubsub.c
	@echo "Building basic_pubsub example..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)
	@echo "Build complete: ./$@"
	@echo "Run with: LD_LIBRARY_PATH=../../../target/debug ./$@"

clean:
	rm -f basic_pubsub

run: basic_pubsub
	LD_LIBRARY_PATH=../../../target/debug ./basic_pubsub

.PHONY: all clean run
