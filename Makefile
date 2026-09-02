.PHONY: build linux windows check clean run

WIN_TARGET := x86_64-pc-windows-gnu
WIN_CC     := x86_64-w64-mingw32-gcc

build: linux windows

linux:
	cargo build --release

windows:
	@if command -v $(WIN_CC) >/dev/null 2>&1; then \
		cargo build --release --target $(WIN_TARGET); \
	else \
		echo "warning: $(WIN_CC) not found; skipping Windows build."; \
		echo "         install with: sudo apt install gcc-mingw-w64-x86-64"; \
	fi

check:
	cargo check

clean:
	cargo clean

run:
	cargo run --release -- $(ARGS)
