CC ?= gcc
CFLAGS = -O2 -Wall -Wextra -std=c17 -D_GNU_SOURCE
LDFLAGS = -ljansson

TARGET = far2l-asar
SRC = src/far2l-asar.c
CFG_USER = cfg/custom.ini
CFG_SYS = cfg/custom.system.ini

VERSION := $(strip $(shell cat VERSION 2>/dev/null || echo 1.0.1))
CFLAGS += -DAPP_VERSION='"$(VERSION)"'
ARCH := $(shell dpkg --print-architecture)
PKG_DIR = build/deb
DIST_DIR = dist
DEB_FILE = $(DIST_DIR)/$(TARGET)_$(VERSION)_$(ARCH).deb
STANDALONE_BIN = $(DIST_DIR)/$(TARGET)-$(VERSION)-standalone-linux-$(shell uname -m)

PREFIX ?= $(HOME)/.local/bin
FAR2L_CFG_DIR ?= $(HOME)/.config/far2l/plugins/multiarc
CUSTOM_INI = $(FAR2L_CFG_DIR)/custom.ini

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	strip $(TARGET)

test: $(TARGET)
	python3 tests/test_asar.py

install: $(TARGET) $(CFG_USER)
	install -Dm755 $(TARGET) $(PREFIX)/$(TARGET)
	mkdir -p $(FAR2L_CFG_DIR)
	@if [ ! -f "$(CUSTOM_INI)" ]; then \
		install -Dm644 $(CFG_USER) "$(CUSTOM_INI)"; \
		echo "Created $(CUSTOM_INI)"; \
	else \
		cp "$(CUSTOM_INI)" "$(CUSTOM_INI).bak"; \
		awk 'BEGIN{skip=0} /^\[ASAR\]/{skip=1; next} /^\[/{skip=0} !skip{print}' "$(CUSTOM_INI).bak" > "$(CUSTOM_INI).tmp"; \
		printf "\n" >> "$(CUSTOM_INI).tmp"; \
		cat $(CFG_USER) >> "$(CUSTOM_INI).tmp"; \
		mv "$(CUSTOM_INI).tmp" "$(CUSTOM_INI)"; \
		echo "Updated [ASAR] section in $(CUSTOM_INI) (backup: $(CUSTOM_INI).bak)"; \
	fi

standalone: $(SRC)
	mkdir -p $(DIST_DIR)
	$(CC) $(CFLAGS) -o $(STANDALONE_BIN) $(SRC) -Wl,-Bstatic -ljansson -Wl,-Bdynamic
	strip --strip-all $(STANDALONE_BIN)
	@echo "Built standalone binary: $(STANDALONE_BIN)"
	@ldd $(STANDALONE_BIN) || true

deb: $(TARGET) $(CFG_SYS) packaging/postinst README.md
	rm -rf $(PKG_DIR)
	mkdir -p $(DIST_DIR) $(PKG_DIR)/DEBIAN
	install -Dm755 $(TARGET) $(PKG_DIR)/usr/bin/$(TARGET)
	install -Dm644 $(CFG_SYS) $(PKG_DIR)/usr/share/$(TARGET)/custom.ini
	install -Dm644 README.md $(PKG_DIR)/usr/share/doc/$(TARGET)/README.md
	install -Dm755 packaging/postinst $(PKG_DIR)/DEBIAN/postinst
	printf "Package: %s\n" "$(TARGET)" > $(PKG_DIR)/DEBIAN/control
	printf "Version: %s\n" "$(VERSION)" >> $(PKG_DIR)/DEBIAN/control
	printf "Section: utils\n" >> $(PKG_DIR)/DEBIAN/control
	printf "Priority: optional\n" >> $(PKG_DIR)/DEBIAN/control
	printf "Architecture: %s\n" "$(ARCH)" >> $(PKG_DIR)/DEBIAN/control
	printf "Depends: libc6, libjansson4\n" >> $(PKG_DIR)/DEBIAN/control
	printf "Maintainer: bigvax <bigvax@://github.com>\n" >> $(PKG_DIR)/DEBIAN/control
	printf "Description: Native Electron ASAR backend for far2l MultiArc\n" >> $(PKG_DIR)/DEBIAN/control
	printf " Lightweight C implementation for viewing, extracting and updating\n" >> $(PKG_DIR)/DEBIAN/control
	printf " Electron .asar archives in far2l without Node.js or Python.\n" >> $(PKG_DIR)/DEBIAN/control
	chmod 755 $(PKG_DIR)/DEBIAN
	dpkg-deb --build --root-owner-group $(PKG_DIR) $(DEB_FILE)
	rm -rf build
	@echo "Built package: $(DEB_FILE)"

clean:
	rm -rf $(TARGET) build $(DIST_DIR)


bump-patch:
	@python3 -c 'from pathlib import Path; p=Path("VERSION"); maj,min,pat=map(int,p.read_text().strip().split(".")); v=f"{maj}.{min}.{pat+1}"; p.write_text(v+"\n"); print("Version bumped to", v)'

bump-minor:
	@python3 -c 'from pathlib import Path; p=Path("VERSION"); maj,min,pat=map(int,p.read_text().strip().split(".")); v=f"{maj}.{min+1}.0"; p.write_text(v+"\n"); print("Version bumped to", v)'

bump-major:
	@python3 -c 'from pathlib import Path; p=Path("VERSION"); maj,min,pat=map(int,p.read_text().strip().split(".")); v=f"{maj+1}.0.0"; p.write_text(v+"\n"); print("Version bumped to", v)'


BUNDLE_TAR = $(DIST_DIR)/$(TARGET)-$(VERSION)-linux-$(shell uname -m).tar.gz

bundle: $(TARGET) $(CFG_USER) README.md
	mkdir -p $(DIST_DIR)/bundle
	install -Dm755 $(TARGET) $(DIST_DIR)/bundle/$(TARGET)
	install -Dm644 $(CFG_USER) $(DIST_DIR)/bundle/custom.ini
	install -Dm644 README.md $(DIST_DIR)/bundle/README.md
	tar -czf $(BUNDLE_TAR) -C $(DIST_DIR)/bundle .
	rm -rf $(DIST_DIR)/bundle
	@echo "Built release archive: $(BUNDLE_TAR)"

.PHONY: all test install standalone deb bundle bump-patch bump-minor bump-major clean
