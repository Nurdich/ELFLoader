# 构建说明

## 编译 Go 版本

### 前置要求

- Go 1.21 或更高版本
- GCC 或 Clang（用于 CGO）
- 开发工具（make、git 等）

### 步骤

```bash
cd go

# 下载依赖
go mod tidy

# 编译（启用 CGO）
CGO_ENABLED=1 go build -o elfloader ./cmd/elfloader

# 或者使用 Make（如果有 Makefile）
make build
```

### 编译示例

```bash
# 编译示例目标文件
cd examples
make

# 返回上级目录
cd ..
```

### 测试

```bash
# 测试 ELF 加载（不执行）
./elfloader examples/hello.o

# 预期输出:
# Function loaded at address: 0x...
# Arguments: 0 bytes
# Note: Execution of loaded code is not yet implemented in pure Go.
```

## 架构支持

当前支持：
- x86_64 (amd64)
- x86 (i386)

计划支持：
- ARM
- ARM64

## 已知问题

1. **代码执行**：纯 Go 版本无法执行加载的代码，需要 CGO 或汇编实现
2. **符号查找**：依赖 `dlsym`，需要 CGO 支持
3. **平台限制**：某些平台特定功能可能不可用

## 开发模式

启用调试输出：

```bash
# 添加 debug 标签
go build -tags debug -o elfloader ./cmd/elfloader
```

## 交叉编译

```bash
# Linux x86_64
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o elfloader-linux-amd64 ./cmd/elfloader

# Linux x86
GOOS=linux GOARCH=386 CGO_ENABLED=1 go build -o elfloader-linux-386 ./cmd/elfloader

# 注意：交叉编译时 CGO 需要对应平台的工具链
```
