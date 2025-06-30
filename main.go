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

	singbox_wireguard "a/singbox/wireguard"
	"a/wgcf"
	xray_wireguard "a/xray/wireguard"

	"golang.zx2c4.com/wireguard/device"
)

var (
	tun_v4      string
	tun_v6      string
	private_key string
	public_key  string
	client_id   string
	mtu         = 1280

	try       = 3
	file_path = "result.txt"
	n         = 200
	endpoint  = ""

	private_key_bytes        []byte
	public_key_bytes         []byte
	private_key_bytes_string string
	public_key_bytes_string  string

	client_id_bytes []byte
)

func init() {
	tun_v4, tun_v6, private_key, public_key, client_id = wgcf.Get()
	// fmt.Println("tun_v4", tun_v4)
	// fmt.Println("tun_v6", tun_v6)
	// fmt.Println("private_key", private_key)
	// fmt.Println("public_key", public_key)
	// fmt.Println("client_id", client_id)

	private_key_bytes, _ = base64.StdEncoding.DecodeString(private_key)
	public_key_bytes, _ = base64.StdEncoding.DecodeString(public_key)
	private_key_bytes_string = hex.EncodeToString(private_key_bytes)
	public_key_bytes_string = hex.EncodeToString(public_key_bytes)

	client_id_bytes, _ = base64.StdEncoding.DecodeString(client_id)
}

func IP(endpoint string) (v4, v6 string) {
	t, _, client, err := xray_wireguard.GetTun([]string{tun_v4, tun_v6}, mtu)
	if err != nil {
		log.Panic(err)
	}

	// bind := xray_wireguard.GetBind(true, true, client_id_bytes)
	// dev := device.NewDevice(t, bind, device.NewLogger(device.LogLevelSilent, ""))

	bind := singbox_wireguard.GetBind(endpoint, client_id_bytes)
	dev := device.NewDevice(t, bind, device.NewLogger(device.LogLevelSilent, ""))

	// dev := device.NewDevice(t, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))

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

	v4 = ""
	v6 = ""

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api4.ipify.org/")
		if err != nil {
			// fmt.Println("api4", err)
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			// fmt.Println("api4", err)
			time.Sleep(1 * time.Second)
			continue
		}
		v4 = string(body)
		break
	}

	for i := 0; i < try; i++ {
		resp, err := client.Get("http://api6.ipify.org/")
		if err != nil {
			// fmt.Println("api6", err)
			time.Sleep(1 * time.Second)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			// fmt.Println("api6", err)
			time.Sleep(1 * time.Second)
			continue
		}
		v6 = string(body)
		break
	}

	dev.Close()
	return v4, v6
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
		v4, v6 := IP(endpoint)
		fmt.Println("v4:", v4)
		fmt.Println("v6:", v6)
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

			t, _, client, err := xray_wireguard.GetTun([]string{tun_v4, tun_v6}, mtu)
			if err != nil {
				log.Panic(err)
			}
			bind := singbox_wireguard.GetBind("127.0.0.1:1", client_id_bytes)
			dev := device.NewDevice(t, bind, device.NewLogger(device.LogLevelSilent, ""))
			for ep := range tasks {
				bind.SetEP(netip.MustParseAddrPort(ep))
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
		fmt.Fprintf(w1, "%s | %s | %s\n", r.Endpoint, r.V4, r.V6)
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
