.PHONY: all clean

### Opt & C code compliance
CFLAGS = -O3 \
         -Wall -Wextra -Wpedantic \
         -Werror \
         -Wunused -Wundef \
         -Wconversion -Wsign-conversion -Wdouble-promotion -Wfloat-equal \
         -Wwrite-strings \
         -Wformat=2 -Wformat-security -Werror=format-security \
         -Wstrict-prototypes -Wold-style-definition \
         -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls \
         -Wshadow \
         -fstack-protector-strong \
         -D_FORTIFY_SOURCE=2 \
         -Isrc
         
LDFLAGS = -lm -lpthread -lssl -lcrypto -lcurl -ljansson -lzmq -lsqlite3

SRCS = src/solostratum.c src/stats.c
OBJS = $(SRCS:.c=.o)
TARGET = solostratum

all: $(TARGET)
	@echo "=========================================="
	@echo "Build complete!"
	@echo "Binary: $(TARGET)"
	@echo "Size: $$(du -h $(TARGET) | cut -f1)"
	@echo "Built: $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo "=========================================="
	@echo "Run with (daemon mode): ./$(TARGET) -c solostratum.conf -d"
	@echo "Run with (terminal mode): ./$(TARGET) -c solostratum.conf"
	@echo "=========================================="

$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Linking complete!"

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled $@"

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "Clean complete!"
