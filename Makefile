.PHONY: build check clean run

build:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

run:
	cargo run --release -- $(ARGS)
