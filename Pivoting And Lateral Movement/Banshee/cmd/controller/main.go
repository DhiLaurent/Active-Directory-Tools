package main

import (
        "bufio"
        "crypto/rand"
        "crypto/rsa"
        "crypto/tls"
        "crypto/x509"
        "crypto/x509/pkix"
        "encoding/pem"
        "flag"
        "fmt"
        "io"
        "log"
        "math/big"
        "net"
        "os"
        "os/exec"
        "strings"
        "sync"
        "time"

        "github.com/hashicorp/yamux"
        "github.com/songgao/water"
)

type AgentSession struct {
        ID         string
        RemoteAddr string
        Hostname   string
        Session    *yamux.Session
        CtrlStream net.Conn
        Conn       net.Conn
        Active     bool
}

var (
        sessions   = make(map[string]*AgentSession)
        sessionsMu sync.Mutex
        currentID  string
)

func generateRealisticCert() (tls.Certificate, error) {
        priv, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                return tls.Certificate{}, err
        }

        template := x509.Certificate{
                SerialNumber: big.NewInt(time.Now().Unix()),
                Subject: pkix.Name{
                        Organization: []string{"Microsoft Corporation"},
                        CommonName:   "Microsoft Windows Update Root Authority",
                },
                NotBefore:             time.Now().Add(-24 * time.Hour),
                NotAfter:              time.Now().Add(365 * 24 * time.Hour),
                KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
                ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
                BasicConstraintsValid: true,
                IsCA:                  true,
        }

        derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
        if err != nil {
                return tls.Certificate{}, err
        }

        certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
        keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

        return tls.X509KeyPair(certPEM, keyPEM)
}

func setupTun(name string, ipAddr string) *water.Interface {
        c := water.Config{
                DeviceType: water.TUN,
        }
        c.Name = name

        ifce, err := water.New(c)
        if err != nil {
                log.Fatalf("[-] Erro ao criar tun (%s): %v", name, err)
        }

        exec.Command("ip", "addr", "add", ipAddr, "dev", ifce.Name()).Run()
        exec.Command("ip", "link", "set", "dev", ifce.Name(), "up").Run()

        return ifce
}

func main() {
        listenIP := flag.String("ip", "0.0.0.0", "Endereço IP para escutar")
        listenPort := flag.String("port", "8080", "Porta para escutar conexões")
        flag.Parse()

        cert, err := generateRealisticCert()
        if err != nil {
                log.Fatalf("[-] Erro ao gerar certificado: %v", err)
        }

        tlsConfig := &tls.Config{
                Certificates: []tls.Certificate{cert},
                MinVersion:   tls.VersionTLS12,
        }

        bindAddr := fmt.Sprintf("%s:%s", *listenIP, *listenPort)
        listener, err := tls.Listen("tcp", bindAddr, tlsConfig)
        if err != nil {
                log.Fatalf("[-] Erro ao iniciar listener tls em %s: %v", bindAddr, err)
        }
        defer listener.Close()

        fmt.Println(`
        ██████╗  █████╗ ███╗   ██╗███████╗██╗  ██╗███████╗███████╗
        ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║  ██║██╔════╝██╔════╝
        ██████╔╝███████║██╔██╗ ██║███████╗███████║█████╗  █████╗  
        ██╔══██╗██╔══██║██║╚██╗██║╚════██║██╔══██║██╔══╝  ██╔══╝  
        ██████╔╝██║  ██║██║ ╚████║███████║██║  ██║███████╗███████╗
        `)
        fmt.Printf("[*] Banshee Tunneling Framework ouvindo em %s...\n", bindAddr)

        go func() {
                for {
                        conn, err := listener.Accept()
                        if err != nil {
                                continue
                        }

                        session, err := yamux.Server(conn, nil)
                        if err != nil {
                                conn.Close()
                                continue
                        }

                        ctrlStream, err := session.AcceptStream()
                        if err != nil {
                                session.Close()
                                conn.Close()
                                continue
                        }

                        metaBuf := make([]byte, 256)
                        n, _ := ctrlStream.Read(metaBuf)
                        hostname := string(metaBuf[:n])
                        if hostname == "" {
                                hostname = "unknown-host"
                        }

                        id := fmt.Sprintf("%d", time.Now().Unix()%10000)

                        sessionsMu.Lock()
                        sessions[id] = &AgentSession{
                                ID:         id,
                                RemoteAddr: conn.RemoteAddr().String(),
                                Hostname:   hostname,
                                Session:    session,
                                CtrlStream: ctrlStream,
                                Conn:       conn,
                                Active:     true,
                        }
                        sessionsMu.Unlock()

                        fmt.Printf("\n[+] Agent joined: id=%s name=%s remote=%s\nbanshee » ", id, hostname, conn.RemoteAddr().String())
                }
        }()

        reader := bufio.NewReader(os.Stdin)
        for {
                sessionsMu.Lock()
                sess, inSession := sessions[currentID]
                sessionsMu.Unlock()

                if !inSession {
                        currentID = ""
                        fmt.Print("banshee » ")
                } else {
                        fmt.Printf("[Agent : %s] » ", sess.Hostname)
                }

                line, err := reader.ReadString('\n')
                if err != nil {
                        break
                }
                cmd := strings.TrimSpace(line)
                if cmd == "" {
                        continue
                }

                parts := strings.Fields(cmd)
                switch parts[0] {
                case "sessions", "session":
                        sessionsMu.Lock()
                        fmt.Println("\nID   | HOSTNAME       | ENDEREÇO IP")
                        fmt.Println("---------------------------------------")
                        for id, s := range sessions {
                                fmt.Printf("%-4s | %-14s | %s\n", id, s.Hostname, s.RemoteAddr)
                        }
                        fmt.Println()
                        sessionsMu.Unlock()

                case "use":
                        if len(parts) < 2 {
                                fmt.Println("Uso: use <ID_da_sessao>")
                                continue
                        }
                        sessionsMu.Lock()
                        if _, exists := sessions[parts[1]]; exists {
                                currentID = parts[1]
                                fmt.Printf("[*] Entrando no contexto da sessão %s\n", currentID)
                        } else {
                                fmt.Println("[-] Sessão não encontrada.")
                        }
                        sessionsMu.Unlock()

                case "background", "back":
                        currentID = ""
                        fmt.Println("[*] Retornando ao menu principal.")

                case "ifconfig":
                        if !inSession {
                                fmt.Println("[-] Execute dentro de uma sessão (use <ID>)")
                                continue
                        }
                        sess.CtrlStream.Write([]byte("ifconfig\n"))
                        respBuf := make([]byte, 4096)
                        sess.CtrlStream.SetReadDeadline(time.Now().Add(2 * time.Second))
                        n, _ := sess.CtrlStream.Read(respBuf)
                        sess.CtrlStream.SetReadDeadline(time.Time{})
                        fmt.Println(string(respBuf[:n]))

                case "autoroute":
                        if !inSession {
                                fmt.Println("[-] Execute dentro de uma sessão (use <ID>)")
                                continue
                        }

                        sess.CtrlStream.Write([]byte("autoroute\n"))
                        respBuf := make([]byte, 2048)
                        sess.CtrlStream.SetReadDeadline(time.Now().Add(2 * time.Second))
                        n, err := sess.CtrlStream.Read(respBuf)
                        sess.CtrlStream.SetReadDeadline(time.Time{})
                        if err != nil || n == 0 {
                                fmt.Println("[-] Erro ao obter rotas do agente.")
                                continue
                        }

                        rawRoutes := string(respBuf[:n])
                        routes := strings.Split(strings.TrimSpace(rawRoutes), ",")
                        if len(routes) == 0 || routes[0] == "" {
                                fmt.Println("[-] Nenhuma rota encontrada no agente.")
                                continue
                        }

                        fmt.Println("\n? Select routes to add:")
                        for i, r := range routes {
                                fmt.Printf("  [%d] %s\n", i+1, r)
                        }
                        fmt.Print("Escolha o número da rota para tunelar (ou 0 para cancelar): ")

                        choiceStr, _ := reader.ReadString('\n')
                        choiceStr = strings.TrimSpace(choiceStr)
                        var choice int
                        fmt.Sscanf(choiceStr, "%d", &choice)

                        if choice <= 0 || choice > len(routes) {
                                fmt.Println("[*] Operação cancelada.")
                                continue
                        }

                        selectedRoute := routes[choice-1]
                        tunName := fmt.Sprintf("banshee%d", time.Now().Unix()%1000)
                        fmt.Printf("[*] Usando nome de interface: %s\n", tunName)

                        tunStream, err := sess.Session.OpenStream()
                        if err != nil {
                                fmt.Printf("[-] Erro ao abrir stream de túnel: %v\n", err)
                                continue
                        }
                        defer tunStream.Close()

                        ifce := setupTun(tunName, "10.10.10.1/24")
                        defer ifce.Close()

                        fmt.Printf("[*] Criando rota para %s via %s...\n", selectedRoute, tunName)
                        exec.Command("ip", "route", "add", selectedRoute, "dev", tunName).Run()

                        fmt.Print("? Start the tunnel? (y/N) ")
                        confirm, _ := reader.ReadString('\n')
                        confirm = strings.TrimSpace(strings.ToLower(confirm))
                        if confirm != "y" && confirm != "yes" {
                                fmt.Println("[*] Túnel cancelado.")
                                exec.Command("ip", "route", "del", selectedRoute, "dev", tunName).Run()
                                continue
                        }

                        fmt.Println("[+] Túnel L3 ativo! Pressione Ctrl+C ou feche para encerrar.")

                        go func() {
                                buf := make([]byte, 2048)
                                for {
                                        n, err := ifce.Read(buf)
                                        if err != nil {
                                                break
                                        }
                                        if n > 0 {
                                                pktLen := n
                                                lenBuf := []byte{byte(pktLen >> 8), byte(pktLen & 0xff)}
                                                tunStream.Write(lenBuf)
                                                tunStream.Write(buf[:pktLen])
                                        }
                                }
                        }()

                        lenBuf := make([]byte, 2)
                        for {
                                _, err := io.ReadFull(tunStream, lenBuf)
                                if err != nil {
                                        break
                                }
                                pktLen := int(lenBuf[0])<<8 | int(lenBuf[1])
                                if pktLen <= 0 || pktLen > 2000 {
                                        break
                                }
                                pktBuf := make([]byte, pktLen)
                                _, err = io.ReadFull(tunStream, pktBuf)
                                if err != nil {
                                        break
                                }
                                ifce.Write(pktBuf)
                        }
                        exec.Command("ip", "route", "del", selectedRoute, "dev", tunName).Run()
                        fmt.Println("[-] Túnel L3 encerrado.")

                case "exit", "quit":
                        fmt.Println("Saindo...")
                        os.Exit(0)

                case "help":
                        if !inSession {
                                fmt.Println("Comandos disponíveis:")
                                fmt.Println("  sessions             - Lista todas as sessões ativas")
                                fmt.Println("  use <ID>             - Seleciona uma sessão para interagir")
                                fmt.Println("  exit                 - Encerra o controlador")
                        } else {
                                fmt.Println("Comandos da Sessão:")
                                fmt.Println("  ifconfig             - Lista as interfaces de rede da máquina alvo")
                                fmt.Println("  autoroute            - Descoberta interativa de rotas e subnets")
                                fmt.Println("  background           - Retorna ao menu principal")
                        }
                default:
                        fmt.Printf("Comando desconhecido: %s. Digite 'help' para ajuda.\n", parts[0])
                }
        }
}
