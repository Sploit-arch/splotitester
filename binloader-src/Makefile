# binloader — self-contained FW-independent payload receiver
# Modeled on the proven ps4-hen installer Makefile (same toolchain that built
# the working 14.02 hen.bin), but links NO libPS4.a: the stub is fully
# freestanding (raw syscalls only), so the binary has zero undefined symbols,
# zero relocations against external data, and no GOT bootstrap to fail.

LIBPS4  := $(PS4SDK)/libPS4

CC      := gcc
OBJCOPY := objcopy
READELF := readelf
RM      := rm
ODIR    := build
SDIR    := source
MAPFILE := binloader.map
TARGET  := ../binloader.bin

# Compiler flags — same proven set as the installer, plus
# -fno-tree-loop-distribute-patterns so gcc cannot turn our copy loops into
# implicit memcpy() calls (we provide fallback symbols anyway).
OPTIMIZATION := -Os
STANDARDS    := -std=c11 -fno-builtin -nostartfiles -nostdlib -ffreestanding
WARNINGS     := -Wno-unused-const-variable -Wall -Wextra
ARCH_FLAGS   := -masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie
CFLAGS       := -I$(SDIR)/.. $(OPTIMIZATION) $(STANDARDS) $(WARNINGS) $(ARCH_FLAGS) -ffunction-sections -fdata-sections -fno-tree-loop-distribute-patterns

# Linker flags — -no-pie so the flat binary carries no dynamic relocations.
LFLAGS  := -Xlinker -T linker.x -Xlinker -Map=$(MAPFILE) -Wl,--build-id=none -Wl,--gc-sections -Wl,-z,noexecstack -no-pie

CFILES  := $(wildcard $(SDIR)/*.c)
SFILES  := $(wildcard $(SDIR)/*.c.s) $(wildcard $(SDIR)/*.s)
OBJS    := $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

.PHONY: all
all: $(TARGET)

$(TARGET): $(ODIR) $(OBJS)
	@echo "Linking $(TARGET)..."
	@$(CC) crt0.s $(ODIR)/*.o -o temp.t $(CFLAGS) $(LFLAGS)
	@$(READELF) -r temp.t > relocations.txt
	@echo "  relocations: $$(wc -l < relocations.txt) lines (relocations.txt)"
	@$(READELF) -d temp.t | grep -q NEEDED && (echo "  ERROR: dynamic NEEDED entries present"; exit 1) || echo "  no dynamic dependencies"
	@$(OBJCOPY) -O binary temp.t $(TARGET)
	@$(RM) -f temp.t
	@echo "Build complete: $(TARGET)"

$(ODIR)/%.o: $(SDIR)/%.c | $(ODIR)
	@$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s | $(ODIR)
	@$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir -p $@

.PHONY: clean
clean:
	@echo "Cleaning..."
	@$(RM) -rf $(TARGET) $(MAPFILE) $(ODIR) temp.t relocations.txt
