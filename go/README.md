# ELFLoader - Go Version

这是 ELFLoader 项目的 Go 语言实现版本。ELFLoader 是一个用于在内存中加载和执行 ELF 目标文件（`.o` 文件）的工具。

## 功能特性

- ✅ ELF 文件解析和验证
- ✅ 内存段加载和管理
- ✅ 符号解析（内部和外部）
- ✅ 重定位处理（x86 和 x86_64）
- ✅ Beacon Object File (BOF) API 兼容层
- ✅ 跨平台支持（Linux、macOS、FreeBSD、OpenBSD）

## 项目结构

```
go/
├── cmd/
│   └── elfloader/          # 主程序入口
│       └── main.go
├── pkg/
│   ├── elfloader/          # ELF 加载器核心
│   │   ├── loader.go       # 主加载逻辑
│   │   ├── relocation.go   # 重定位处理
│   │   └── symbols.go      # 符号解析
│   └── beacon/             # Beacon API 兼容层
│       └── api.go          # Beacon API 实现
├── go.mod                  # Go 模块定义
└── README.md              # 本文件
```

## 编译和安装

### 前置要求

- Go 1.21 或更高版本
- GCC 或 Clang（用于编译测试目标文件）
- Linux、macOS、FreeBSD 或 OpenBSD 操作系统

### 编译步骤

```bash
cd go

# 初始化 Go 模块（如果需要）
go mod tidy

# 编译主程序
go build -o elfloader ./cmd/elfloader

# 或者安装到 $GOPATH/bin
go install ./cmd/elfloader
```

## 使用方法

### 基本用法

```bash
# 加载并执行 ELF 目标文件
./elfloader /path/to/objectfile.o

# 带十六进制编码参数
./elfloader /path/to/objectfile.o 48656c6c6f
```

### 创建测试目标文件

创建一个简单的 C 测试文件 `test.c`:

```c
#include <stdio.h>

// 入口函数必须命名为 "go"
int go(unsigned char* args, int len) {
    printf("Hello from ELF object!\n");
    if (len > 0) {
        printf("Received %d bytes of arguments\n", len);
    }
    return 0;
}
```

编译为目标文件：

```bash
# x86_64
gcc -c -fPIC test.c -o test.o

# x86 (32-bit)
gcc -m32 -c -fPIC test.c -o test.o
```

运行：

```bash
./elfloader test.o
```

## Beacon API 兼容

Go 版本实现了以下 Beacon API 函数，与 Cobalt Strike BOF 兼容：

### 数据解析函数
- `BeaconDataParse` - 初始化数据解析器
- `BeaconDataInt` - 提取 32 位整数
- `BeaconDataShort` - 提取 16 位短整数
- `BeaconDataLength` - 获取剩余数据长度
- `BeaconDataExtract` - 提取长度前缀的二进制数据

### 格式化函数
- `BeaconFormatAlloc` - 分配格式缓冲区
- `BeaconFormatReset` - 重置格式缓冲区
- `BeaconFormatFree` - 释放格式缓冲区
- `BeaconFormatAppend` - 追加数据
- `BeaconFormatPrintf` - 格式化追加
- `BeaconFormatToString` - 转换为字符串
- `BeaconFormatInt` - 追加整数

### 输出函数
- `BeaconPrintf` - 格式化输出
- `BeaconOutput` - 原始数据输出
- `BeaconIsAdmin` - 检查管理员权限

### 系统函数
- `getEnviron` - 获取环境变量
- `getOSName` - 获取操作系统名称

## 架构支持

- ✅ x86_64 (AMD64)
- ✅ x86 (i386)
- ❌ ARM (计划中)
- ❌ ARM64 (计划中)

## 重定位类型支持

### x86_64
- `R_X86_64_64` - 直接 64 位重定位
- `R_X86_64_PC32` - PC 相对 32 位重定位
- `R_X86_64_PLT32` - PLT 相对 32 位重定位

### x86
- `R_386_32` - 直接 32 位重定位
- `R_386_PC32` - PC 相对 32 位重定位

## 与 C 版本的区别

1. **实现语言**: Go vs C
2. **内存安全**: Go 版本使用了更安全的内存管理
3. **性能**: C 版本可能在某些场景下性能更好
4. **可移植性**: Go 版本更容易跨平台编译
5. **CGO 依赖**: Go 版本需要 CGO 来实现 dlsym 符号查找

## 限制和注意事项

⚠️ **重要说明**：

1. **代码执行支持**: Go 版本现在通过 CGO 包装器支持执行加载的代码！

   **当前状态**: Go 版本可以：
   - ✅ 解析 ELF 文件结构
   - ✅ 加载段到内存
   - ✅ 解析符号表
   - ✅ 处理重定位（x86/x86_64）
   - ✅ 找到入口点函数
   - ✅ **执行加载的代码**（通过 CGO）

   **已测试功能**：
   - ✅ 基本函数调用和返回值
   - ✅ 参数传递
   - ⚠️ 外部库函数调用（部分支持，简单函数可用）

2. **CGO 要求**:
   - 符号解析需要 CGO (`CGO_ENABLED=1`)
   - 代码执行需要 CGO 包装器

3. **编译选项**:
   - 建议使用 `-fno-pic -fno-plt` 编译目标文件
   - 避免过于复杂的 GOT/PLT 依赖

4. **内存权限**: 需要适当的系统权限来修改内存保护

5. **安全性**: 在生产环境中使用时需要谨慎，确保只加载可信的目标文件

## 调试

设置环境变量启用调试输出：

```bash
export GODEBUG=cgocheck=0  # 禁用严格的 CGO 检查（仅用于调试）
./elfloader test.o
```

## 示例

### 使用原始 C 版本的示例

原始 C 版本提供了多个示例目标文件在 `SA/src/` 目录中：

- `uname.o` - 系统信息
- `whoami.o` - 用户信息
- `cat.o` - 读取文件
- `find.o` - 查找文件
- 等等...

这些示例也可以用 Go 版本加载（只要架构兼容）。

## 故障排除

### 常见问题

1. **"symbol not found" 错误**
   - 确保所需的共享库已安装
   - 检查符号名称是否正确
   - 验证 CGO 是否正确配置

2. **"failed to allocate memory" 错误**
   - 检查系统内存是否充足
   - 验证是否有足够的权限

3. **"unsupported architecture" 错误**
   - 确保目标文件与当前架构匹配
   - 使用正确的编译器标志编译目标文件

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

遵循原项目的 BSD 许可证。

## 相关链接

- [原始 C 版本 ELFLoader](../)
- [ELF 文件格式规范](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [Cobalt Strike BOF](https://www.cobaltstrike.com/help-beacon-object-files)
