# ReproGen Makefile

CC_MUSL ?= musl-gcc
CC ?= gcc
CFLAGS = -Wall -O2 -static
PROGRAM = reprogen
SRC = src/reprogen.c

.PHONY: all clean musl standard

all: musl

# Default build with musl (preferred for smaller binary size)
musl:
	@echo "Building with musl libc (static binary)..."
	@if command -v $(CC_MUSL) > /dev/null; then \
		$(CC_MUSL) $(CFLAGS) $(SRC) -o $(PROGRAM); \
		echo "Build successful!"; \
		ls -lh $(PROGRAM); \
	else \
		echo "musl-gcc not found, falling back to standard gcc"; \
		$(MAKE) standard; \
	fi

# Fallback to standard gcc with static linking
standard:
	@echo "Building with standard gcc (static binary)..."
	$(CC) $(CFLAGS) $(SRC) -o $(PROGRAM)
	@echo "Build successful!"
	@ls -lh $(PROGRAM)

# Clean build artifacts
clean:
	rm -f $(PROGRAM)

# Install to /usr/local/bin (requires appropriate permissions)
install: all
	install -m 755 $(PROGRAM) /usr/local/bin/$(PROGRAM)

# Run tests
test: all
	@echo "Creating test directory..."
	@mkdir -p test_output
	@echo "Generating a test file..."
	./$(PROGRAM) -d test_output -s 4096 -n 1
	@echo "Verifying reproducibility..."
	@ID=$$(ls test_output | head -1); \
	./$(PROGRAM) -d test_output -s 4096 -i $$ID; \
	echo "Test complete!"