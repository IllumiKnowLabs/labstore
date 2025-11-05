BIN_DIR := bin
BACKEND_DIR := backend
FRONTEND_DIR := web
BACKEND_CMD := $(BIN_DIR)/labstore-server
FRONTEND_BUILD_DIR := $(FRONTEND_DIR)/build

.PHONY: all backend frontend build run clean

all: build

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

BACKEND_SRCS := $(shell find $(BACKEND_DIR) -name "*.go")

$(BACKEND_CMD): $(BACKEND_SRCS) | $(BIN_DIR)
	cd $(BACKEND_DIR) && go build -o ../$(BACKEND_CMD) ./cmd/labstore-server

backend: $(BACKEND_CMD)

frontend:
	cd $(FRONTEND_DIR) && npm install
	cd $(FRONTEND_DIR) && npm run build

build: backend frontend

run: build
	set -a; . ./.env; set +a; \
	(cd $(BACKEND_DIR) && ../$(BACKEND_CMD) serve --debug &) && \
	(cd $(FRONTEND_DIR) && npm run preview -- --port 5123)

clean:
	rm -rf $(BIN_DIR)
	rm -rf $(FRONTEND_DIR)/node_modules $(FRONTEND_DIR)/.svelte-kit $(FRONTEND_BUILD_DIR)
