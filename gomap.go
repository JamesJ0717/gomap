package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sparrc/go-ping"
	"golang.org/x/sync/semaphore"
)

//PortScanner : struct
type PortScanner struct {
	ip    net.IP
	lock  *semaphore.Weighted
	ports []Port
}

//Port : struct for data from JSON
type Port struct {
	Port    float64 `json:"port"`
	Service string  `json:"service"`
}

func ulimit() int64 {
	out, err := exec.Command("ulimit", "-n").Output()
	if err != nil {
		panic(err)
	}

	s := strings.TrimSpace(string(out))

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}

	return i
}

func scanPort(ip net.IP, port int, timeout time.Duration) bool {
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			scanPort(ip, port, timeout)
		}
		// fmt.Println(err.Error())
		return false
	}

	conn.Close()
	return true
}

func isUp(ps PortScanner) int {
	pinger, err := ping.NewPinger(ps.ip.String())
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	pinger.Timeout = 4 * time.Second
	pinger.Count = 4
	pinger.Run()

	if pinger.Statistics().PacketsRecv == 0 {
		return 1
	}

	return 0
}

func getService(port int, ports []Port) string {
	var service string
	for _, serv := range ports {
		if int(serv.Port) == port {
			service = serv.Service
			return service
		}
		service = "unknown"
	}
	return service
}

func (ps *PortScanner) start(l int, timeout time.Duration) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	name := ""
	if ps.ip.IsLoopback() {
		name += "localhost"
	} else {
		name += func() string {
			names, err := net.LookupAddr(ps.ip.String())
			if err != nil {
				fmt.Println(err.Error())
				return ps.ip.String()
			}
			return names[0]
		}()
	}
	fmt.Printf("IP Address %s, Hostname %s\n", ps.ip, name)
	if isUp(*ps) == 1 {
		fmt.Println("Host may be Down!")
		return
	}

	openPorts := make([]int, 0)
	for port := 1; port <= l; port++ {
		ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			// service := service(ps.ip, strconv.Itoa(port))
			defer ps.lock.Release(1)
			if scanPort(ps.ip, port, timeout) {
				openPorts = append(openPorts, port)
			}
			wg.Done()
		}(port)
	}
	wg.Wait()
	for i := 0; i < len(openPorts); i++ {
		fmt.Printf("{port: %d open, \t service: %s} \n", openPorts[i], getService(openPorts[i], ps.ports))
	}
	fmt.Printf("There are %d ports open and %d ports closed. \n", len(openPorts), (l - len(openPorts)))
}

func main() {
	jsonFile, err := os.Open("./tcp.json")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var result []Port
	json.Unmarshal(byteValue, &result)

	p := flag.Int("p", 1024, "Specify the upper bounds of the scan.")
	ip := flag.String("ip", "8.8.8.8", "Specify the IP Address to scan.")
	host := flag.String("host", "www.owasp.org", "Specify the hostname to scan.")
	ipRange := flag.Int("range", 24, "Define an IP range for scanning.")

	flag.Parse()

	psip := func() net.IP {
		if strings.Compare(*host, "www.owasp.org") != 0 {
			return func(hostname string) net.IP {
				names, err := net.LookupIP(hostname)
				if err != nil {
					fmt.Println(err.Error())
				}
				// fmt.Println(names[0])
				return names[0]
			}(*host)
		}
		return net.ParseIP(*ip)
	}()

	ps := &PortScanner{
		ip:    psip,
		lock:  semaphore.NewWeighted(ulimit()),
		ports: result,
	}

	if *ipRange != 0 {
		// ips := int(math.Pow(2, float64(32-*ipRange)))
		// fmt.Println(ips)
	}

	ps.start(*p, 500*time.Millisecond)
}
