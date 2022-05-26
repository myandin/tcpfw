package main

import (
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    "unsafe"
)

var (
    localAddr  *string = flag.String("listen", ":8443", "listen address:port or just :port")
    remoteAddr *string = flag.String("protect", "example.com:443", "protected address")

    connLimit *int     = flag.Int("connlimit", 10, "limit connects per ip")
    rpsLimit  *int     = flag.Int("rpslimit", 10, "limit rps per ip")
    banTime   *float64 = flag.Float64("bantime", 600, "blocking time of the banned ip (seconds)")

    accessLog *string = flag.String("access", "tcpfw.access.log", "full path to log file with access IPs")
    bannedLog *string = flag.String("banned", "tcpfw.banned.log", "full path to log file with banned IPs")

    connPerIp      = map[string]int{}
    connPerIPMutex = sync.Mutex{}

    connectionsCount uint64

    rpsPerIp sync.Map
    bannedIp sync.Map

    accessLogChan = make(chan string)
    bannedLogChan = make(chan string)
)

func main() {
    flag.Parse()

    fmt.Printf("Listen address: %v\nRemote address: %v\n\n", *localAddr, *remoteAddr)

    listener, err := net.Listen("tcp", *localAddr)
    if err != nil {
        panic(err)
    }

    go access_log()
    go banned_log()
    go unban()
    go monitor()

    for {
        localConn, err := listener.Accept()
        if err != nil {
            log.Println("error accepting connection", err)
            continue
        }

        remoteIP := strings.Split(localConn.RemoteAddr().String(), ":")[0]

        if isBanned(remoteIP) {
            localConn.Close()
            continue
        }

        connPerIPMutex.Lock()
        connections, ok := connPerIp[remoteIP]
        connPerIPMutex.Unlock()

        if ok && connections >= *connLimit {
            bannedIp.Store(remoteIP, time.Now())
            bannedLogChan <- remoteIP + " [" + time.Now().Format("2006-01-02 15:04:05") + "] Banned due to connection limit"
            localConn.Close()
            continue
        }

        connPerIPMutex.Lock()
        c := connPerIp[remoteIP]
        connPerIp[remoteIP] = c + 1
        connPerIPMutex.Unlock()

        atomic.AddUint64(&connectionsCount, 1)
        accessLogChan <- remoteIP + " [" + time.Now().Format("2006-01-02 15:04:05") + "] Connected"
        go handle(localConn, remoteIP)
    }
}

func access_log() {
    file, err := os.OpenFile(*accessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Error message: %s\n", err)
        os.Exit(1)
    }
    for v := range accessLogChan {
        file.Write(str2bytes(v + "\n"))
    }
}

func banned_log() {
    file, err := os.OpenFile(*bannedLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Error message: %s\n", err)
        os.Exit(1)
    }
    for v := range bannedLogChan {
        file.Write(str2bytes(v + "\n"))
    }
}

func unban() {
    for {
        bannedIp.Range(func(ip, time_banned interface{}) bool {
            tmp := time_banned.(time.Time)
            if used := time.Since(tmp); used.Seconds() >= *banTime {
                bannedIp.Delete(ip.(string))
            }
            return true
        })
        time.Sleep(time.Second * 1)
    }
}

func monitor() {
    for {
        rps := 0
        currentConn := uint64(0)
        bannedIP := 0
        rpsPerIp.Range(func(ip, times interface{}) bool {
            rps++
            if times.(int) >= *rpsLimit {
                bannedIp.Store(ip.(string), time.Now())
                bannedLogChan <- ip.(string) + " [" + time.Now().Format("2006-01-02 15:04:05") + "] Banned due to rps limit"
            }
            rpsPerIp.Delete(ip.(string))
            return true
        })

        currentConn = atomic.LoadUint64(&connectionsCount)

        bannedIp.Range(func(ip, time_banned interface{}) bool {
            bannedIP++
            return true
        })
        fmt.Printf("Active connections: %d Banned IP: %d Current RPS: %d \n", currentConn, bannedIP, rps)
        time.Sleep(time.Second)
    }
}

func isBanned(remoteIP string) bool {
    _, exists := bannedIp.Load(remoteIP)
    return exists
}

func handle(localConn net.Conn, remoteIP string) {
    defer localConn.Close()

    defer func() {
        connPerIPMutex.Lock()
        connections := connPerIp[remoteIP]
        if connections == 0 {
            connPerIPMutex.Unlock()
            return
        }
        nc := connections - 1
        if nc == 0 {
            delete(connPerIp, remoteIP)
        } else {
            connPerIp[remoteIP] = nc
        }
        connPerIPMutex.Unlock()
        atomic.AddUint64(&connectionsCount, ^uint64(0))
    }()

    if localConn, ok := localConn.(*net.TCPConn); ok {
        localConn.SetNoDelay(false)
    }

    var remoteConn net.Conn
    requestsPerConnection := 0

    for {
        localConn.SetDeadline(time.Now().Add(10 * time.Second))

        if isBanned(remoteIP) {
            return
        }
        if requestsPerConnection >= *rpsLimit {
            return
        }
        buf := make([]byte, 8192)
        n, err := localConn.Read(buf)
        if err != nil {
            if remoteConn != nil {
                remoteConn.Close()
            }
            return
        }
        request := buf[:n]
        if remoteConn == nil {
            remoteConn, err = net.DialTimeout("tcp", *remoteAddr, time.Second*10)
            if err != nil {
                //                localConn.Write(str2bytes(errMsg))
                return
            }
            if remoteConn, ok := remoteConn.(*net.TCPConn); ok {
                remoteConn.SetNoDelay(false)
            }
            go func() {
                defer remoteConn.Close()
                go io.Copy(remoteConn, localConn)
                io.Copy(localConn, remoteConn)
                remoteConn.Close()
                localConn.Close()
            }()
        }

        remoteConn.SetDeadline(time.Now().Add(10 * time.Second))
        remoteConn.Write(request)
        requestsPerConnection++
        rps, ok := rpsPerIp.Load(remoteIP)
        if ok {
            rpsPerIp.Store(remoteIP, rps.(int)+1)
        } else {
            rpsPerIp.Store(remoteIP, 1)
        }
    }
}

func str2bytes(s string) []byte {
    x := (*[2]uintptr)(unsafe.Pointer(&s))
    h := [3]uintptr{x[0], x[1], x[1]}
    return *(*[]byte)(unsafe.Pointer(&h))
}

func bytes2str(s []byte) string {
    return *(*string)(unsafe.Pointer(&s))
}
