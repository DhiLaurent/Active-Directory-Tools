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
        "os/signal"
        "strings"
        "sync"
        "syscall"
        "time"

        "github.com/hashicorp/yamux"
        "github.com/songgao/water"
)

type AgentSession struct {
        ID            string
        RemoteAddr    string
        Hostname      string
        Session       *yamux.Session
        CtrlStream    net.Conn
        Conn          net.Conn
        ActiveTunName string
        ActiveRoute   string
        TunnelActive  bool
        mu            sync.Mutex
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

func cleanupAllRoutes() {
        sessionsMu.Lock()
        defer sessionsMu.Unlock()
        for _, sess := range sessions {
                sess.mu.Lock()
                if sess.ActiveRoute != "" && sess.ActiveTunName != "" {
                        exec.Command("ip", "route", "del", sess.ActiveRoute, "dev", sess.ActiveTunName).Run()
                        fmt.Printf("[*] Rota removida do kernel: %s via %s\n", sess.ActiveRoute, sess.ActiveTunName)
                }
                sess.mu.Unlock()
        }
}

func setupSigHandler() {
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
        go func() {
                <-sigChan
                fmt.Println("\n[*] Sinal de encerramento recebido. Limpando rotas e encerrando Banshee...")
                cleanupAllRoutes()
                os.Exit(0)
        }()
}

func main() {
        listenIP := flag.String("ip", "0.0.0.0", "Endereço IP para escutar")
        listenPort := flag.String("port", "8080", "Porta para escutar conexões")
        flag.Parse()

        setupSigHandler()

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
        fmt.Printf("[*] Banshee Pivoting/Port Forwarding Framework ouvindo em %s...\n", bindAddr)

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

                        sess := &AgentSession{
                                ID:         id,
                                RemoteAddr: conn.RemoteAddr().String(),
                                Hostname:   hostname,
                                Session:    session,
                                CtrlStream: ctrlStream,
                                Conn:       conn,
                        }

                        sessionsMu.Lock()
                        sessions[id] = sess
                        sessionsMu.Unlock()

                        fmt.Printf("\n[+] Agent joined: id=%s name=%s remote=%s\nbanshee » ", id, hostname, conn.RemoteAddr().String())


                        go func(s *AgentSession) {
                                ticker := time.NewTicker(10 * time.Second)
                                defer ticker.Stop()
                                for range ticker.C {
                                        s.CtrlStream.SetWriteDeadline(time.Now().Add(3 * time.Second))
                                        _, err := s.CtrlStream.Write([]byte("ping\n"))
                                        s.CtrlStream.SetWriteDeadline(time.Time{})
                                        if err != nil {
                                                sessionsMu.Lock()
                                                s.mu.Lock()
                                                if s.ActiveRoute != "" && s.ActiveTunName != "" {
                                                        exec.Command("ip", "route", "del", s.ActiveRoute, "dev", s.ActiveTunName).Run()
                                                }
                                                s.mu.Unlock()
                                                s.Session.Close()
                                                s.Conn.Close()
                                                delete(sessions, s.ID)
                                                if currentID == s.ID {
                                                        currentID = ""
                                                }
                                                sessionsMu.Unlock()
                                                fmt.Printf("\n[-] Agent %s (%s) desconectado por timeout.\nbanshee » ", s.ID, s.Hostname)
                                                return
                                        }
                                }
                        }(sess)
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
                        sess.mu.Lock()
                        tunnelStatus := "OFF"
                        if sess.TunnelActive {
                                tunnelStatus = fmt.Sprintf("TUN:%s", sess.ActiveRoute)
                        }
                        sess.mu.Unlock()
                        fmt.Printf("[Agent : %s | %s] » ", sess.Hostname, tunnelStatus)
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
                        fmt.Println("\nID   | HOSTNAME       | ENDEREÇO IP         | TÚNEIS ATIVOS")
                        fmt.Println("-------------------------------------------------------------")
                        for id, s := range sessions {
                                s.mu.Lock()
                                route := s.ActiveRoute
                                if route == "" {
                                        route = "Nenhum"
                                }
                                s.mu.Unlock()
                                fmt.Printf("%-4s | %-14s | %-19s | %s\n", id, s.Hostname, s.RemoteAddr, route)
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

                        sess.mu.Lock()
                        if sess.TunnelActive {
                                sess.mu.Unlock()
                                fmt.Println("[-] Já existe um túnel L3 ativo nesta sessão. Use 'stoptunnel' para encerrá-lo antes de abrir outro.")
                                continue
                        }
                        sess.mu.Unlock()

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

                        fmt.Print("? Start the tunnel? (y/N) ")
                        confirm, _ := reader.ReadString('\n')
                        confirm = strings.TrimSpace(strings.ToLower(confirm))
                        if confirm != "y" && confirm != "yes" {
                                fmt.Println("[*] Túnel cancelado.")
                                continue
                        }

                        tunName := fmt.Sprintf("banshee%d", time.Now().Unix()%1000)
                        fmt.Printf("[*] Usando nome de interface: %s\n", tunName)

                        tunStream, err := sess.Session.OpenStream()
                        if err != nil {
                                fmt.Printf("[-] Erro ao abrir stream de túnel: %v\n", err)
                                continue
                        }

                        ifce := setupTun(tunName, "10.10.10.1/24")

                        fmt.Printf("[*] Criando rota para %s via %s...\n", selectedRoute, tunName)
                        exec.Command("ip", "route", "add", selectedRoute, "dev", tunName).Run()

                        sess.mu.Lock()
                        sess.ActiveTunName = tunName
                        sess.ActiveRoute = selectedRoute
                        sess.TunnelActive = true
                        sess.mu.Unlock()

                        fmt.Println("[+] Túnel L3 ativo em background! Você pode continuar navegando e interagir com outras sessões.")

                        go func(s *AgentSession, ifc *water.Interface, stream net.Conn, tName, route string) {
                                defer stream.Close()
                                defer ifc.Close()

                                go func() {
                                        buf := make([]byte, 2048)
                                        for {
                                                n, err := ifc.Read(buf)
                                                if err != nil {
                                                        break
                                                }
                                                if n > 0 {
                                                        pktLen := n
                                                        lenBuf := []byte{byte(pktLen >> 8), byte(pktLen & 0xff)}
                                                        stream.Write(lenBuf)
                                                        stream.Write(buf[:pktLen])
                                                }
                                        }
                                }()

                                lenBuf := make([]byte, 2)
                                for {
                                        _, err := io.ReadFull(stream, lenBuf)
                                        if err != nil {
                                                break
                                        }
                                        pktLen := int(lenBuf[0])<<8 | int(lenBuf[1])
                                        if pktLen <= 0 || pktLen > 2000 {
                                                break
                                        }
                                        pktBuf := make([]byte, pktLen)
                                        _, err = io.ReadFull(stream, pktBuf)
                                        if err != nil {
                                                break
                                        }
                                        ifc.Write(pktBuf)
                                }

                                exec.Command("ip", "route", "del", route, "dev", tName).Run()
                                s.mu.Lock()
                                s.ActiveTunName = ""
                                s.ActiveRoute = ""
                                s.TunnelActive = false
                                s.mu.Unlock()
                                fmt.Printf("\n[-] Túnel L3 da sessão %s encerrado.\nbanshee » ", s.ID)
                        }(sess, ifce, tunStream, tunName, selectedRoute)

                case "stoptunnel":
                        if !inSession {
                                fmt.Println("[-] Execute dentro de uma sessão (use <ID>)")
                                continue
                        }
                        sess.mu.Lock()
                        if !sess.TunnelActive {
                                sess.mu.Unlock()
                                fmt.Println("[-] Nenhum túnel ativo nesta sessão.")
                                continue
                        }
                        exec.Command("ip", "route", "del", sess.ActiveRoute, "dev", sess.ActiveTunName).Run()
                        sess.TunnelActive = false
                        sess.ActiveRoute = ""
                        sess.ActiveTunName = ""
                        sess.mu.Unlock()
                        fmt.Println("[*] Túnel encerrado manualmente.")

                case "exit", "quit":
                        fmt.Println("Saindo...")
                        cleanupAllRoutes()
                        os.Exit(0)

                case "help":
                        if !inSession {
                                fmt.Println("Comandos disponíveis:")
                                fmt.Println("  sessions             - Lista todas as sessões ativas e túneis")
                                fmt.Println("  use <ID>             - Seleciona uma sessão para interagir")
                                fmt.Println("  exit                 - Encerra o controlador e limpa rotas")
                        } else {
                                fmt.Println("Comandos da Sessão:")
                                fmt.Println("  ifconfig             - Lista as interfaces de rede da máquina alvo")
                                fmt.Println("  autoroute            - Abre túnel L3 em background para a sub-rede")
                                fmt.Println("  stoptunnel           - Encerra o túnel L3 atual da sessão")
                                fmt.Println("  background           - Retorna ao menu principal")
                        }
                default:
                        fmt.Printf("Comando desconhecido: %s. Digite 'help' para ajuda.\n", parts[0])
                }
        }
}
