ifdef RELEASE
OPENSSL_CONFIG_TYPE = --release
TCGTPM_CFLAGS = -O3 -DDEBUG=NO
else
OPENSSL_CONFIG_TYPE = --debug
TCGTPM_CFLAGS = -g -O0 -DDEBUG=YES
endif

DEPS_DIR = $(CURDIR)/deps

LIBCRT_DIR = $(DEPS_DIR)/libcrt
OPENSSL_DIR = $(DEPS_DIR)/openssl
TCGTPM_DIR = $(DEPS_DIR)/tpm-20-ref/TPMCmd

LIBCRT = $(LIBCRT_DIR)/libcrt.a
LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a

LIBTPM_TARGET = Tpm_CoreLib
LIBTPM = $(TCGTPM_INSTALL_DIR)/lib64/lib$(LIBTPM_TARGET).a

LIBPLATFORM_TARGET = Tpm_PlatformLib
LIBPLATFORM = $(TCGTPM_INSTALL_DIR)/lib64/lib$(LIBPLATFORM_TARGET).a

LIBTPMBIGNUM_TARGET = Tpm_CryptoLib_TpmBigNum
LIBTPMBIGNUM = $(TCGTPM_INSTALL_DIR)/lib64/lib$(LIBTPMBIGNUM_TARGET).a

LIBBNMATH_TARGET = Tpm_CryptoLib_Math_Ossl
LIBBNMATH = $(TCGTPM_INSTALL_DIR)/lib64/lib$(LIBBNMATH_TARGET).a

OPENSSL_MAKEFILE = $(OPENSSL_DIR)/Makefile
TCGTPM_CORE_BUILD_DIR = $(TCGTPM_DIR)/build/libtpm
TCGTPM_PLATFORM_BUILD_DIR = $(TCGTPM_DIR)/build/platform
TCGTPM_INSTALL_DIR = $(TCGTPM_DIR)/build/install

LIBS = $(LIBCRT) $(LIBCRYPTO) $(LIBBNMATH) $(LIBTPMBIGNUM) $(LIBTPM) $(LIBPLATFORM)

OUT_DIR ?= $(CWD)

all: $(OUT_DIR)/libtcgtpm.a

$(OUT_DIR)/libtcgtpm.a: $(LIBS)
	rm -f $@
	ar rcsTPD $@ $^

.PHONY: $(LIBCRT)

# libcrt
$(LIBCRT):
	$(MAKE) -C $(LIBCRT_DIR)

# openssl
$(LIBCRYPTO): $(OPENSSL_MAKEFILE) $(LIBCRT)
	$(MAKE) -C $(OPENSSL_DIR) -j$$(nproc)

$(OPENSSL_MAKEFILE):
	(cd $(OPENSSL_DIR) && \
		./Configure \
			--config=$(DEPS_DIR)/openssl_svsm.conf \
			--api=1.1.1 \
			SVSM \
			disable-legacy \
			no-afalgeng \
			no-aria \
			no-asm \
			no-async \
			no-atexit \
			no-autoerrinit \
			no-autoload-config \
			no-bf \
			no-blake2 \
			no-capieng \
			no-cast \
			no-chacha \
			no-cmac \
			no-cmp \
			no-cms \
			no-ct \
			no-deprecated \
			no-des \
			no-dgram \
			no-dh \
			no-docs \
			no-dsa \
			no-dso \
			no-dtls \
			no-dtls1 \
			no-dtls1_2 \
			no-dtls1_2-method \
			no-dtls1-method \
			no-dynamic-engine \
			no-ec2m \
			no-ecx  \
			no-egd \
			no-engine \
			no-err \
			no-filenames \
			no-gost \
			no-http  \
			no-hw \
			no-idea \
			no-ktls \
			no-makedepend \
			no-md4 \
			no-mdc2 \
			no-module \
			no-multiblock \
			no-nextprotoneg \
			no-ocb \
			no-ocsp \
			no-padlockeng \
			no-pic \
			no-poly1305 \
			no-posix-io \
			no-psk \
			no-quic \
			no-rc2 \
			no-rc4 \
			no-rfc3779 \
			no-rmd160 \
			no-scrypt \
			no-seed \
			no-shared \
			no-siphash \
			no-siv \
			no-sm2 \
			no-sm2-precomp  \
			no-sm4 \
			no-sock \
			no-srp \
			no-srtp \
			no-sse2 \
			no-ssl \
			no-ssl3-method \
			no-ssl-trace \
			no-static-engine \
			no-stdio \
			no-tests \
			no-thread-pool \
			no-threads \
			no-tls1 \
			no-tls1_1 \
			no-tls1_1-method \
			no-tls1_2 \
			no-tls1_2-method \
			no-tls1_3 \
			no-tls1-method \
			no-ts \
			no-ui-console \
			no-uplink \
			no-whirlpool \
			--with-rand-seed=getrandom \
			$(OPENSSL_CONFIG_TYPE) \
			-I$(LIBCRT_DIR)/include \
			-Wl,rpath=$(LIBCRT_DIR) -lcrt)

TCGTPM_CFLAGS += -static -nostdinc -fno-stack-protector -fPIE -mno-sse -mno-red-zone
TCGTPM_CFLAGS += -DFILE_BACKED_NV=NO
TCGTPM_CFLAGS += -I$(LIBCRT_DIR)/include
TCGTPM_CFLAGS += -I$(OPENSSL_DIR)/include

$(LIBTPMBIGNUM) $(LIBBNMATH) $(LIBTPM): $(LIBCRYPTO)
	cmake -B $(TCGTPM_CORE_BUILD_DIR) -S $(TCGTPM_DIR)/. \
		--install-prefix $(TCGTPM_INSTALL_DIR) \
		-DCMAKE_C_FLAGS="${TCGTPM_CFLAGS}" \
		-DOPENSSL_CRYPTO_LIBRARY="$(LIBCRYPTO)" \
		-DOPENSSL_INCLUDE_DIR="$(OPENSSL_DIR)/include" \
		-Duser_TpmConfiguration_Dir="$(DEPS_DIR)/TpmConfiguration" \
		-DTpm_BuildOption_LibOnly=ON
	cmake --build $(TCGTPM_CORE_BUILD_DIR) -j$$(nproc)
	cmake --install $(TCGTPM_CORE_BUILD_DIR)

$(LIBPLATFORM): $(LIBCRYPTO) $(LIBTPM)
	cmake -B $(TCGTPM_PLATFORM_BUILD_DIR) -S $(TCGTPM_DIR)/Platform \
		--install-prefix $(TCGTPM_INSTALL_DIR) \
		-DCMAKE_C_FLAGS="${TCGTPM_CFLAGS}"
	cmake --build $(TCGTPM_PLATFORM_BUILD_DIR) -j$$(nproc)
	cmake --install $(TCGTPM_PLATFORM_BUILD_DIR)

clean:
	make -C $(LIBCRT_DIR) clean
	-make -C $(OPENSSL_DIR) clean
	-make -C $(TCGTPM_CORE_BUILD_DIR) clean
	-make -C $(TCGTPM_PLATFORM_BUILD_DIR) clean
	rm -f libtcgtpm.a

distclean: clean
	rm -f $(OPENSSL_MAKEFILE)
	rm -rf $(TCGTPM_CORE_BUILD_DIR) $(TCGTPM_PLATFORM_BUILD_DIR) $(TCGTPM_INSTALL_DIR)

.PHONY: all clean distclean
