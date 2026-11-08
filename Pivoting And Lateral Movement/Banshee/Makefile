all: clean build

clean:
        @echo "[*] Limpando diretório bin/..."
        @rm -rf bin/*

build:
        @echo "[*] Compilando Controlador (Linux)..."
        go build -o bin/controller ./cmd/controller/main.go
        @echo "[*] Compilando Agente (Linux)..."
        GOOS=linux GOARCH=amd64 go build -o bin/agent ./cmd/agent
        @echo "[*] Compilando Agente (Windows)..."
        GOOS=windows GOARCH=amd64 go build -o bin/agent.exe ./cmd/agent
        @echo "[+] Build concluído com sucesso!"
