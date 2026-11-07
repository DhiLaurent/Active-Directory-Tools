.PHONY: all controller agent-linux agent-windows clean

all: controller agent-linux agent-windows
        @echo ""
        @echo "[+] Sucesso! Todos os binários foram gerados na pasta bin/:"
        @echo "    ├── bin/controller     (Controlador Linux)"
        @echo "    ├── bin/agent          (Agente Linux)"
        @echo "    └── bin/agent.exe      (Agente Windows)"

controller:
        @echo "[*] Compilando Controlador (Linux)..."
        go build -o bin/controller ./cmd/controller/main.go

agent-linux:
        @echo "[*] Compilando Agente (Linux)..."
        go build -o bin/agent ./cmd/agent/main.go

agent-windows:
        @echo "[*] Compilando Agente (Windows .exe)..."
        GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui" -o bin/agent.exe ./cmd/agent/main.go

clean:
        @echo "[*] Limpando diretório bin/..."
        rm -rf bin/*
