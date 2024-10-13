build:
	 go build -o builds/macOS/dev_proxy.dylib -buildmode=c-shared ./cmd/main.go \
	&& go build -o builds/x86_64/dev_proxy.dll -buildmode=c-shared ./cmd/main.go

migrate: 	
	cp -r ./builds/macOS ../Assets/Plugins/YandexGamesSDK/Editor/Plugins/ \
	&& cp -r ./builds/x86_64 ../Assets/Plugins/YandexGamesSDK/Editor/Plugins/
