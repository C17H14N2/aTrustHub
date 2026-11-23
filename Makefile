# aTrust Hub 用 mygo：纯 Go，没有 cgo，也没有前端构建。
#
# 需要 Go 1.27.3 或更新（go.mod 的要求）。
# 想换一个二进制：make GO=/path/to/go。

GO    ?= go
CACHE := $(CURDIR)/.cache

# 国内访问 proxy.golang.org 常常不通，默认走 goproxy.cn。
export GOPROXY ?= https://goproxy.cn,direct
export GOFLAGS ?= -mod=mod

# 只能写仓库目录时（沙箱、临时机）用 make LOCAL=1，缓存落到 .cache/。
ifeq ($(LOCAL),1)
export GOCACHE    ?= $(CACHE)/go-build
export GOMODCACHE ?= $(CACHE)/mod
export GOTMPDIR   ?= $(CACHE)/tmp
endif

.PHONY: all run dev test vet fmt helpers helpers-all build dmg clean

all: run

## run: 直接跑应用
run:
	$(GO) run .

## dev: mygo 的开发模式，改代码自动重启
dev:
	$(GO) tool mygo dev

## test: 配置、存储、SOCKS5 和会话管理的单元测试，不需要窗口
test:
	$(GO) test ./...

## vet: 静态检查
vet:
	$(GO) vet ./...

## fmt: 格式化
fmt:
	$(GO) fmt ./...

## helpers: 本机用：只为 darwin-arm64 编译 TUN 辅助程序（最快）
helpers:
	cd third_party/zju-connect && GOOS=darwin GOARCH=arm64 $(GO) build -o ../../resources/darwin-arm64/zju-connect-multitun ./cmd/multitun

## helpers-all: 编译全部平台的辅助程序（发版用，CI 也会做）
helpers-all:
	cd third_party/zju-connect && GOOS=darwin GOARCH=arm64 $(GO) build -o ../../resources/darwin-arm64/zju-connect-multitun ./cmd/multitun
	cd third_party/zju-connect && GOOS=darwin GOARCH=amd64 $(GO) build -o ../../resources/darwin-amd64/zju-connect-multitun ./cmd/multitun
	cd third_party/zju-connect && GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-H=windowsgui" -o ../../resources/windows-amd64/zju-connect-multitun.exe ./cmd/multitun
	cd third_party/zju-connect && GOOS=windows GOARCH=386 $(GO) build -ldflags "-H=windowsgui" -o ../../resources/windows-386/zju-connect-multitun.exe ./cmd/multitun
	cd third_party/zju-connect && GOOS=windows GOARCH=arm64 $(GO) build -ldflags "-H=windowsgui" -o ../../resources/windows-arm64/zju-connect-multitun.exe ./cmd/multitun

## build: 打包成本机应用（macOS 上是 build/darwin-arm64/aTrustHub.app）
build:
	$(GO) tool mygo build -skip-dmg

## build-debug: 同 build，但保留 WebView 开发者工具（登录窗口按 F12 可打开）
build-debug:
	$(GO) tool mygo build -skip-dmg -debug

## install: 编好并覆盖安装到 /Applications，然后启动（一条命令刷新你正在用的 App）
##  应用有单实例锁：这里先退出正在运行的实例，否则 open 只会激活旧窗口。
install: helpers build
	-osascript -e 'quit app "aTrustHub"' 2>/dev/null || true
	sleep 1
	rm -rf /Applications/aTrustHub.app
	cp -R build/darwin-arm64/aTrustHub.app /Applications/
	open /Applications/aTrustHub.app
	@echo "已安装并启动：/Applications/aTrustHub.app"

## refresh: 同 install，但只重启「本地 build」里的那份，不动 /Applications
##  适合不想覆盖安装、直接从仓库目录跑的场景。
refresh: helpers build
	-osascript -e 'quit app "aTrustHub"' 2>/dev/null || true
	sleep 1
	open build/darwin-arm64/aTrustHub.app
	@echo "已启动本地构建：build/darwin-arm64/aTrustHub.app"

## dmg: 打包并生成磁盘映像（macOS）
dmg:
	$(GO) tool mygo build

## clean: 清掉构建产物
clean:
	rm -rf build .mygo
