BIN_DIR := bin

BACKEND_DIR := backend
BACKEND_CMD := $(BIN_DIR)/labstore-server

FRONTEND_DIR := web
FRONTEND_SRC_DIRS := $(FRONTEND_DIR)/src $(FRONTEND_DIR)/static
FRONTEND_BUILD_DIR := $(FRONTEND_DIR)/build

.PHONY: all backend frontend build run clean

all: build

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

BACKEND_SRCS := $(shell find $(BACKEND_DIR) -name "*.go")

$(BACKEND_CMD): $(BACKEND_SRCS) | $(BIN_DIR)
	cd $(BACKEND_DIR) && go build -o ../$(BACKEND_CMD) ./cmd/labstore-server

backend: $(BACKEND_CMD)

FRONTEND_SRCS := $(shell find $(FRONTEND_SRC_DIRS) -type f)

$(FRONTEND_BUILD_DIR): $(FRONTEND_SRCS)
	cd $(FRONTEND_DIR) && npm ci
	cd $(FRONTEND_DIR) && npm run build

frontend: $(FRONTEND_BUILD_DIR)

build: backend frontend

run: build
	npx dotenv-cli -- npx concurrently \
		-n backend,web \
		-c blue,green \
		"bin/labstore-server serve --debug" \
		"cd web/ && npm run preview -- --port 5123"

clean:
	rm -rf $(BIN_DIR)
	rm -rf $(FRONTEND_DIR)/node_modules $(FRONTEND_DIR)/.svelte-kit $(FRONTEND_BUILD_DIR)
