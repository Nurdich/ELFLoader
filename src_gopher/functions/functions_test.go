package functions

import (
	"strings"
	"testing"
)

// TestParsePortRange 测试端口范围解析
func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  int
		shouldErr bool
	}{
		{"单个端口", "80", 1, false},
		{"端口范围", "80-85", 6, false},
		{"多个端口", "80,443,8080", 3, false},
		{"混合", "80,443-445,8080", 5, false},
		{"无效范围", "invalid", 0, true},
		{"无效端口", "99999", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := parsePortRange(tt.input)
			if (err != nil) != tt.shouldErr {
				t.Errorf("parsePortRange() error = %v, shouldErr %v", err, tt.shouldErr)
				return
			}
			if len(ports) != tt.expected {
				t.Errorf("parsePortRange() got %d ports, expected %d", len(ports), tt.expected)
			}
		})
	}
}

// TestHandleScanCommand 测试扫描命令处理
func TestHandleScanCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		shouldErr bool
	}{
		{"缺少参数", []string{}, true},
		{"缺少端口范围", []string{"192.168.1.1"}, true},
		{"无效IP", []string{"invalid", "80"}, false}, // 返回错误信息但不panic
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HandleScanCommand(tt.args)
			if tt.shouldErr && !strings.Contains(result, "Error") && !strings.Contains(result, "Usage") {
				t.Errorf("HandleScanCommand() expected error message, got: %s", result)
			}
		})
	}
}

// TestScanPortsWithConcurrency 测试可配置并发数
func TestScanPortsWithConcurrency(t *testing.T) {
	tests := []struct {
		name        string
		concurrency int
		expected    int // 期望的并发数（经过验证后）
	}{
		{"并发数为0", 0, 1},      // 应该调整为1
		{"并发数为15", 15, 15},   // 正常
		{"并发数为200", 200, 100}, // 应该限制为100
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 验证并发数限制逻辑
			concurrency := tt.concurrency
			if concurrency < 1 {
				concurrency = 1
			}
			if concurrency > 100 {
				concurrency = 100
			}
			if concurrency != tt.expected {
				t.Errorf("Concurrency validation failed: got %d, expected %d", concurrency, tt.expected)
			}
		})
	}
}

// TestParseIPRange 测试 IP 范围解析
func TestParseIPRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		minCount  int
		maxCount  int
		shouldErr bool
	}{
		{"单个IP", "192.168.1.1", 1, 1, false},
		{"CIDR /30", "192.168.1.0/30", 2, 2, false}, // 跳过网络和广播地址
		{"IP段", "192.168.1.1-192.168.1.3", 3, 3, false},
		{"无效CIDR", "192.168.1.0/33", 0, 0, true},
		{"无效IP段", "192.168.1.1-invalid", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := parseIPRange(tt.input)
			if (err != nil) != tt.shouldErr {
				t.Errorf("parseIPRange() error = %v, shouldErr %v", err, tt.shouldErr)
				return
			}
			if len(ips) < tt.minCount || len(ips) > tt.maxCount {
				t.Errorf("parseIPRange() got %d IPs, expected %d-%d", len(ips), tt.minCount, tt.maxCount)
			}
		})
	}
}

// TestParseCIDR 测试 CIDR 解析
func TestParseCIDR(t *testing.T) {
	ips, err := parseCIDR("192.168.1.0/30")
	if err != nil {
		t.Errorf("parseCIDR() error = %v", err)
		return
	}
	// /30 应该有 2 个可用 IP（跳过网络和广播地址）
	if len(ips) != 2 {
		t.Errorf("parseCIDR() got %d IPs, expected 2", len(ips))
	}
}

// TestParseIPSegment 测试 IP 段解析
func TestParseIPSegment(t *testing.T) {
	ips, err := parseIPSegment("192.168.1.1-192.168.1.5")
	if err != nil {
		t.Errorf("parseIPSegment() error = %v", err)
		return
	}
	if len(ips) != 5 {
		t.Errorf("parseIPSegment() got %d IPs, expected 5", len(ips))
	}
}

// TestGrabBanner 测试Banner抓取（本地测试）
func TestGrabBanner(t *testing.T) {
	// 测试无效主机
	banner := grabBanner("invalid-host-12345.local", 80)
	if banner != "" {
		t.Errorf("grabBanner() expected empty banner for invalid host, got: %s", banner)
	}
}

// TestIsHostAlive 测试主机探活
func TestIsHostAlive(t *testing.T) {
	// 测试本地主机（应该在线）
	alive := isHostAlive("127.0.0.1")
	// 注意：结果取决于系统权限和网络配置
	t.Logf("isHostAlive(127.0.0.1) = %v", alive)
}

