# kernelcache_patcher

将解压后的 iOS kernelcache 中的 Kext，或磁盘上的独立 Kext，重新链接到自行编译的 XNU 内核，生成传统 prelinked kernelcache。

## 构建与测试

需要 `tinyxml2`、`capstone`、`keystone` 和支持 C++17 的编译器。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

测试覆盖虚表映射、类识别、构造/析构函数重定位、plist 引用与架构依赖，以及 ARM64 ADRP 控制流。

## 分析虚表和 ABI

```sh
kernelcache_patcher analyze <本地未剥符号内核> <发布内核> [symbols.json] [--native-only] [--details]
kernelcache_patcher dump-vtable <未剥符号的 Mach-O> <虚表符号名>
kernelcache_patcher inspect-abi <符号模板映像> <待分析映像> <output.json>
```

`analyze` 默认读取发布内核旁的 `<kernelcache>.symbols.json`，并扫描 arm64 `OSMetaClass` 注册调用，恢复类名、父类、实例大小和实例虚表。`--native-only` 禁用 sidecar 和自动类命名，只比较原生符号；`--details` 输出类、注册地址、实例大小和虚函数槽。

原生导出的实例虚表优先于相邻元对象推断。已有非零地址的符号不会被位置猜测覆盖。两侧虚表槽数不同，或已命名虚函数的槽位不符时，拒绝整张虚表的映射。拒绝信息包含原因、槽号、地址和两侧槽数。命令成功只表示存在匹配结果，不代表所有类的 ABI 均兼容。

`dump-vtable` 列出虚函数槽，结合外部重定位显示未解析函数名。`inspect-abi` 生成 JSON，包含类名、父类、实例大小、虚函数槽地址及符号名到地址的映射。模板仅提供名称和结构，输出地址来自待分析映像。

## 制作 kernelcache

```sh
kernelcache_patcher <本地未剥符号内核> <发布内核> <auto|-|符号列表|@符号列表> <Kext目录> <输出内核> [发布内核补丁列表]
```

符号选择方式：

- `auto`：加载可用的 `<发布内核>.symbols.json`。
- `-`：禁用该 sidecar。
- CSV 路径：加载 sidecar，再用 CSV 覆盖。
- `@CSV路径`：只加载指定 CSV，禁用自动 sidecar。

以上方式均保留后续的自动结构分析。CSV 每行是十六进制地址和符号名；以 `#` 开头的行是注释。

```text
# 地址,符号名
0xfffffff001234000,__ZTV7OSArray
```

sidecar 使用地址到名称的扁平 JSON 对象：

```json
{
  "18446744005108056656": "vtable for OSArray"
}
```

### Kext 目录

目录中需要 `kexts.txt`。每行指定目录内的 Kext 相对路径，或发布 kernelcache 中的 bundle ID。磁盘路径可带或不带 `.kext` 后缀。所有所需依赖也必须列入。

```text
ExampleDriver
org.example.driver.Provider
```

支持两种 XML Info.plist 布局：

```text
ExampleDriver.kext/Info.plist
ExampleDriver.kext/<CFBundleExecutable>

ExampleDriver.kext/Contents/Info.plist
ExampleDriver.kext/Contents/MacOS/<CFBundleExecutable>
```

可执行文件名读取 `CFBundleExecutable`，不要求与目录同名。声明了可执行文件却找不到时会报错；未声明可执行文件的纯元数据 Kext 会保留其 personalities 和依赖。

依赖选择优先使用完整的 `OSBundleLibraries_arm64` 字典，存在时替代通用字典，不合并两者。输出保留原有架构字段。plist 的共享 `ID`/`IDREF` 会展开为独立节点，缺失引用、循环引用或重复 ID 会报错。

### 未剥符号参考 Kext

工具从当前目录逐级向上寻找 `kexts/reference`，也可以显式指定：

```sh
KERNELCACHE_PATCHER_REFERENCE_DIR=/path/to/reference-kexts \
  kernelcache_patcher <本地内核> <发布内核> - <Kext目录> <输出内核>
```

参考文件仅提供名称、槽位和相对结构，地址重新从当前源映像计算。无法解析的外部符号使程序返回非零，不输出新缓存。

### 发布内核补丁

可选补丁文件使用发布内核虚拟地址和 32 位补丁值：

```text
# 目标地址
*0xfffffff001234000:
# 补丁值
+d503201f
```

## 重定位与输出

磁盘 Kext 的本地指针按显式重定位记录处理，避免把小整数当作地址。源、目标段映射用于调整指针及外部引用；`kmod_info` 的名称和版本字符数组不参与指针猜测。

ADRP 分析跟踪寄存器复制、条件分支、回跳、调用者保存寄存器和有界跳转表。每个消费者分别计算低 12 位偏移；无法证明的间接分支、冲突目标页或有歧义的位移会使生成失败。代码内数据只通过完整算法常量表或已验证的跳转表结构识别，不按驱动名称或固件地址放行。

打包保留数据段的原始 4 KiB 页内偏移，按 16 KiB 对齐聚合段边界，并修正段权限、zerofill、资源头及已移除的 LINKEDIT 元数据。

工具输出 Mach-O 缓存。平台指令适配、模块完整性重算和离线/启动校验由调用方安排。

## 参考

- [cocoahuke/ioskextdump_ios10](https://github.com/cocoahuke/ioskextdump_ios10)：类名、OSMetaClass 参数、继承与虚表恢复
- [Siguza/iometa](https://github.com/Siguza/iometa)：IOKit 类、虚表和虚方法分析
- [blacktop/ipsw](https://github.com/blacktop/ipsw)：内核与 Kext 分析
