package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"a/wgcf"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	tun_v4      string
	tun_v6      string
	private_key string
	public_key  string
	mtu         = 1280

	try       = 3
	file_path = "result.txt"
	n         = 200
	endpoint  = ""

	private_key_bytes        []byte
	public_key_bytes         []byte
	private_key_bytes_string string
	public_key_bytes_string  string
)

func init() {
	tun_v4, tun_v6, private_key, public_key = wgcf.Get()
	// fmt.Println("tun_v4", tun_v4)
	// fmt.Println("tun_v6", tun_v6)
	// fmt.Println("private_key", private_key)
	// fmt.Println("public_key", public_key)

	private_key_bytes, _ = base64.StdEncoding.DecodeString(private_key)
	public_key_bytes, _ = base64.StdEncoding.DecodeString(public_key)
	private_key_bytes_string = hex.EncodeToString(private_key_bytes)
	public_key_bytes_string = hex.EncodeToString(public_key_bytes)
}

func IP(endpoint string) (v4, v6, ipsb string) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(tun_v4), netip.MustParseAddr(tun_v6)}, // 1
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		mtu)
	if err != nil {
		log.Panic(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	// defer func() {
	// 	dev.Close()
	// }()

	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
allowed_ip=::/0
endpoint=%s
`, private_key_bytes_string, public_key_bytes_string, endpoint))
	if err != nil {
		log.Panic(err)
	}

	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	client := &http.Client{ // client := http.Client
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 1 * time.Second,
	}

	v4 = ""
	v6 = ""
	ipsb = ""

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api4.ipify.org/")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		v4 = string(body)
		break
	}

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api6.ipify.org/")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		v6 = string(body)
		break
	}

	for i := 0; i < try; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://ip.sb/", nil)
		req.Header.Set("user-agent", "curl/7.79.1")
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		ipsb = string(body)
		break
	}

	dev.Close()
	return v4, v6, ipsb
}

func IP2(client *http.Client) (v4, v6 string) {
	v4 = ""
	v6 = ""

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api4.ipify.org/")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		v4 = string(body)
		break
	}

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api6.ipify.org/")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		v6 = string(body)
		break
	}

	return v4, v6
}

func main() {
	// fmt.Println(IP("162.159.195.17:500"))

	flag.IntVar(&mtu, "mtu", 1420, "MTU")
	flag.IntVar(&try, "t", 3, "尝试次数")
	flag.StringVar(&file_path, "f", "result.txt", "输入文件路径")
	flag.IntVar(&n, "n", 200, "并发数")
	flag.StringVar(&endpoint, "ep", "", "测试单个 ep")
	flag.Parse()

	if endpoint != "" {
		v4, v6, ipsb := IP(endpoint)
		fmt.Println("v4:", v4)
		fmt.Println("v6:", v6)
		fmt.Println("ipsb:", ipsb)
		return
	}

	var endpoints []string

	f, err := os.Open(file_path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ep := strings.SplitN(line, " ", 2)[0]
		if ep != "" {
			endpoints = append(endpoints, ep)
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	tasks := make(chan string)
	ch := make(chan struct {
		Endpoint string
		V4       string
		V6       string
	}, len(endpoints))

	for i := 0; i < n; i++ {
		go func() {
			// for ep := range tasks {
			// 	v4, v6 := IP(ep)
			// 	ch <- struct {
			// 		Endpoint string
			// 		V4       string
			// 		V6       string
			// 	}{Endpoint: ep, V4: v4, V6: v6}
			// }
			tun, tnet, err := netstack.CreateNetTUN(
				[]netip.Addr{netip.MustParseAddr(tun_v4), netip.MustParseAddr(tun_v6)},
				[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
				mtu)
			if err != nil {
				log.Panic(err)
			}
			dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
			client := &http.Client{
				Transport: &http.Transport{
					DialContext: tnet.DialContext,
				},
				Timeout: 1 * time.Second,
			}
			for ep := range tasks {
				err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
allowed_ip=::/0
endpoint=%s
`, private_key_bytes_string, public_key_bytes_string, ep))
				if err != nil {
					log.Panic(err)
				}
				err = dev.Up()
				if err != nil {
					log.Panic(err)
				}
				v4, v6 := IP2(client)
				ch <- struct {
					Endpoint string
					V4       string
					V6       string
				}{Endpoint: ep, V4: v4, V6: v6}
				dev.Down()
			}
		}()
	}

	go func() {
		for _, ep := range endpoints {
			tasks <- ep
		}
		close(tasks)
	}()

	results := make([]struct {
		Endpoint string
		V4       string
		V6       string
	}, 0, len(endpoints))
	for i := 0; i < len(endpoints); i++ {
		res := <-ch
		fmt.Printf("\r%d/%d", i+1, len(endpoints))
		if res.V4 != "" || res.V6 != "" {
			results = append(results, res)
		}
	}

	v4Map := make(map[string][]string)
	v6Map := make(map[string][]string)
	for _, r := range results {
		if r.V4 != "" {
			v4Map[r.V4] = append(v4Map[r.V4], r.Endpoint)
		}
		if r.V6 != "" {
			v6Map[r.V6] = append(v6Map[r.V6], r.Endpoint)
		}
	}

	f1, err := os.Create(file_path + ".by_endpoint.txt")
	if err != nil {
		panic(err)
	}
	defer f1.Close()
	w1 := bufio.NewWriter(f1)
	for _, r := range results {
		fmt.Fprintf(w1, "%s %s %s\n", r.Endpoint, r.V4, r.V6)
	}
	w1.Flush()

	f2, err := os.Create(file_path + ".by_ip.txt")
	if err != nil {
		panic(err)
	}
	defer f2.Close()
	w2 := bufio.NewWriter(f2)

	ipMap := make(map[string][]string)
	for v4, eps := range v4Map {
		ipMap[v4] = append(ipMap[v4], eps...)
	}
	for v6, eps := range v6Map {
		ipMap[v6] = append(ipMap[v6], eps...)
	}
	for ip, eps := range ipMap {
		fmt.Fprintf(w2, "%s", ip)
		for _, ep := range eps {
			fmt.Fprintf(w2, " %s", ep)
		}
		fmt.Fprintln(w2)
	}
	w2.Flush()
}
