# ELFLoader Go 版本 - 使用指南

## 快速开始

### 1. 编译 ELFLoader

```bash
cd go
CGO_ENABLED=1 go build -o elfloader ./cmd/elfloader
```

### 2. 创建测试目标文件

创建一个简单的 C 文件 `test.c`:

```c
// 简单示例 - 不依赖外部库
int go(unsigned char* args, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += args[i];
    }
    return sum + 42;
}
```

编译为目标文件：

```bash
gcc -c -fPIC -fno-pic -fno-plt -Wall -m64 test.c -o test.o
```

### 3. 运行

```bash
./elfloader test.o           # 无参数，应该返回 42
./elfloader test.o 010203    # 参数 [1,2,3]，应该返回 48 (42+1+2+3)
```

## 编译选项说明

### 推荐的编译选项

```bash
gcc -c -fPIC -fno-pic -fno-plt -Wall -m64 yourcode.c -o yourcode.o
```

选项说明：
- `-c`: 只编译不链接，生成 .o 目标文件
- `-fPIC`: 生成位置无关代码（某些平台需要）
- `-fno-pic`: 不使用 PIC（简化重定位）
- `-fno-plt`: 不使用 PLT（过程链接表）
- `-Wall`: 启用所有警告
- `-m64`: 64 位代码（或 `-m32` 用于 32 位）

### 为什么使用 -fno-pic 和 -fno-plt？

这些选项简化了生成的代码，减少了对 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 的依赖，使得在运行时加载和重定位更加简单。

## 支持的功能

### ✅ 完全支持

1. **基本计算和逻辑**
   ```c
   int go(unsigned char* args, int len) {
       int result = 0;
       for (int i = 0; i < len; i++) {
           result += args[i] * 2;
       }
       return result;
   }
   ```

2. **指针操作**
   ```c
   int go(unsigned char* args, int len) {
       if (args == 0 || len == 0) {
           return -1;
       }
       return args[0] + args[len-1];
   }
   ```

3. **简单的数据结构**
   ```c
   struct Data {
       int x;
       int y;
   };

   int go(unsigned char* args, int len) {
       struct Data d = {10, 20};
       return d.x + d.y;
   }
   ```

### ⚠️ 部分支持

1. **标准库函数**
   - 简单的 libc 函数可能可用，但不保证
   - 复杂的函数（如 printf, malloc）可能导致崩溃
   - 建议避免使用外部库函数

### ❌ 不支持

1. **线程操作** (pthread等)
2. **复杂的动态内存分配**
3. **文件 I/O** (fopen, fread, 等)
4. **系统调用** (除非明确支持)

## 参数传递

### 十六进制编码

参数必须以十六进制字符串形式传递：

```bash
# 传递字节 [0x01, 0x02, 0x03]
./elfloader test.o 010203

# 传递字符串 "Hello"
./elfloader test.o 48656c6c6f

# 传递更复杂的数据
./elfloader test.o deadbeef12345678
```

### 在 C 代码中接收参数

```c
int go(unsigned char* args, int len) {
    // args: 指向参数数据的指针
    // len: 参数数据的字节长度

    if (len < 4) {
        return -1;  // 参数不足
    }

    // 读取前 4 个字节
    int value = (args[0] << 24) | (args[1] << 16) |
                (args[2] << 8) | args[3];

    return value;
}
```

## 返回值

函数的返回值会被打印出来：

```bash
$ ./elfloader test.o
Function loaded at address: 0x7ea...
Executing function with 0 bytes of arguments...
Function returned: 42
```

返回值是一个 32 位整数（int）。

## 调试

### 检查 ELF 文件

```bash
# 查看段和节
readelf -S test.o

# 查看符号表
readelf -s test.o

# 查看重定位信息
readelf -r test.o
```

### 检查函数是否存在

```bash
nm test.o | grep " go"
```

应该看到类似：
```
0000000000000000 T go
```

## 完整示例

### 示例 1: 计算校验和

```c
// checksum.c
int go(unsigned char* args, int len) {
    unsigned int checksum = 0;
    for (int i = 0; i < len; i++) {
        checksum += args[i];
    }
    return checksum & 0xFFFF;  // 16-bit checksum
}
```

编译和运行：
```bash
gcc -c -fPIC -fno-pic -fno-plt -m64 checksum.c -o checksum.o
./elfloader checksum.o 01020304050607080910
```

### 示例 2: 简单的数据处理

```c
// process.c
int go(unsigned char* args, int len) {
    if (len != 8) {
        return -1;  // 需要正好 8 字节
    }

    // 将 8 字节解释为两个 32 位整数并相加
    int a = (args[0] << 24) | (args[1] << 16) | (args[2] << 8) | args[3];
    int b = (args[4] << 24) | (args[5] << 16) | (args[6] << 8) | args[7];

    return a + b;
}
```

编译和运行：
```bash
gcc -c -fPIC -fno-pic -fno-plt -m64 process.c -o process.o
./elfloader process.o 0000000a00000014  # 10 + 20 = 30
```

### 示例 3: 条件逻辑

```c
// logic.c
int go(unsigned char* args, int len) {
    if (len == 0) {
        return 0;
    }

    int result = 0;
    for (int i = 0; i < len; i++) {
        if (args[i] > 128) {
            result += args[i] - 128;
        } else {
            result += args[i];
        }
    }

    return result;
}
```

## 故障排除

### 问题: "function 'go' not found"

**原因**: 目标文件中没有名为 "go" 的符号。

**解决方案**:
1. 确保函数名为 `go`
2. 不要声明为 `static`
3. 使用 `nm test.o | grep go` 检查

### 问题: "unsupported relocation type"

**原因**: 使用了不支持的重定位类型。

**解决方案**:
1. 添加 `-fno-pic -fno-plt` 编译选项
2. 避免使用复杂的外部库函数

### 问题: Segmentation fault

**原因**:
1. 重定位错误
2. 调用了未解析的外部函数
3. 内存访问越界

**解决方案**:
1. 简化代码，移除外部库调用
2. 检查数组访问是否越界
3. 使用 `readelf -r test.o` 检查重定位

## 性能说明

Go 版本的 ELFLoader 主要用于：
- 学习 ELF 文件格式
- 开发和测试
- 轻量级代码动态加载

对于生产环境或性能关键的应用，建议使用原始 C 版本。

## 下一步

- 查看 `examples/` 目录中的更多示例
- 阅读 `README.md` 了解架构详情
- 参考原始 C 版本的 `SA/src/` 目录中的复杂示例
