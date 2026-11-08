package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		fmt.Printf("[-] Erro ao executar %s %v: %v\n", name, args, err)
		os.Exit(1)
	}
}

func main() {
	fmt.Println("[*] Verificando e baixando dependências...")
	runCmd("go", "mod", "download")

	fmt.Println("[*] Limpando diretório bin/...")
	_ = os.RemoveAll("bin")
	err := os.MkdirAll("bin", 0755)
	if err != nil {
		fmt.Printf("[-] Erro ao criar diretório bin/: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Compilando Controlador (Linux)...")
	runCmd("go", "build", "-o", filepath.Join("bin", "controller"), filepath.Join("cmd", "controller", "main.go"))

	fmt.Println("[*] Compilando Agente (Linux)...")
	cmdLinux := exec.Command("go", "build", "-o", filepath.Join("bin", "agent"), filepath.Join("cmd", "agent", "main.go"))
	cmdLinux.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	cmdLinux.Stdout = os.Stdout
	cmdLinux.Stderr = os.Stderr
	cmdLinux.Run()

	fmt.Println("[*] Compilando Agente (Windows)...")
	cmdWin := exec.Command("go", "build", "-o", filepath.Join("bin", "agent.exe"), filepath.Join("cmd", "agent", "main.go"))
	cmdWin.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	cmdWin.Stdout = os.Stdout
	cmdWin.Stderr = os.Stderr
	cmdWin.Run()

	fmt.Println("[+] Build concluído com sucesso na pasta bin/!")
}
