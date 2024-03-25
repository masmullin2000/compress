.PHONY: debug
debug:
	cargo build
	cp target/debug/compress .

.PHONY: release
release:
	cargo build --target x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/compress .

.PHONY: tiny
tiny:
	RUSTFLAGS='-C panic=abort -Zlocation-detail=none' \
		cargo +nightly build --release --target x86_64-unknown-linux-musl \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort
	upx --ultra-brute target/x86_64-unknown-linux-musl/release/compress
	cp target/x86_64-unknown-linux-musl/release/compress .


.PHONY: tinygnu
tinygnu:
	RUSTFLAGS='-C panic=abort -Zlocation-detail=none' \
		cargo +nightly build --release --target x86_64-unknown-linux-gnu \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort
	upx --ultra-brute target/x86_64-unknown-linux-gnu/release/compress
	cp target/x86_64-unknown-linux-gnu/release/compress .

.PHONY: clean
clean:
	cargo clean
	rm -f compress
