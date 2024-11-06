.PHONY: build build-mac build-windows clean

UNITY_PLUGIN_PATH=../Assets/Plugins/YandexGamesSDK/Editor/Plugins

build: build-mac-universal build-windows

build-mac:
	# Build for macOS (x86_64)
	mkdir -p $(UNITY_PLUGIN_PATH)/macOS
	CC="clang -arch x86_64" \
	CGO_CFLAGS="-arch x86_64" \
	CGO_LDFLAGS="-arch x86_64" \
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -v -o $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_x86_64.dylib -buildmode=c-shared ./cmd

build-mac-arm64:
	# Build for macOS (arm64)
	mkdir -p $(UNITY_PLUGIN_PATH)/macOS
	CC="clang -arch arm64" \
	CGO_CFLAGS="-arch arm64" \
	CGO_LDFLAGS="-arch arm64" \
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -v -o $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_arm64.dylib -buildmode=c-shared ./cmd

build-mac-universal: build-mac build-mac-arm64
	# Create a universal binary
	lipo -create -output $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy.dylib \
		$(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_x86_64.dylib \
		$(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_arm64.dylib
	# Remove individual architecture files
	rm $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_x86_64.dylib
	rm $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy_arm64.dylib

build-windows:
	# Build for Windows (amd64)
	mkdir -p $(UNITY_PLUGIN_PATH)/x86_64
	# If cross-compiling from macOS to Windows, set CC to the cross-compiler
	CC=x86_64-w64-mingw32-gcc \
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -v -o $(UNITY_PLUGIN_PATH)/x86_64/libdev_proxy.dll -buildmode=c-shared ./cmd

clean:
	rm -f $(UNITY_PLUGIN_PATH)/macOS/libdev_proxy.dylib
	rm -f $(UNITY_PLUGIN_PATH)/x86_64/libdev_proxy.dll
