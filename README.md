## 简介
该工具用于对自行编译的xnu内核进行一些修改，可以将iOS的内核缓存中的Kext或者自己编写的Kext添加进去，制作成一个自定义的内核缓存(针对iOS的格式)。

> 目前测试可以对iPad Mini 4，iPadOS 12.4(16G77)的内核(4903.270.47)以及iPadOS 16.3的内核(8792.82.2)正常解析，可能有BUG。

## 依赖
需要安装`tinyxml2`、`capstone`、`keystone`库
## 构建
```
mkdir build
cmake ..
make
```
## 使用方法
```
kernelcache_patcher <编译内核> <iOS内核> <符号列表文件> <Kext目录> <输出内核> [iOS内核补丁列表文件]
```
- 内核需要解压之后的，可以使用`TrungNguyen1909/t8030-tools`的`bootstrap_scripts/decompress_lzss.py`工具进行解压:
 
    [https://github.com/TrungNguyen1909/qemu-t8030-tools/blob/master/bootstrap_scripts/decompress_lzss.py](https://github.com/TrungNguyen1909/qemu-t8030-tools/blob/master/bootstrap_scripts/decompress_lzss.py)
### 符号列表
该文件用于手动指定iOS内核中提取Kext的符号和地址。

新建一个空文本，写法比较简单，格式如下：
```
# 注释
地址,符号名
```
> 例子: 0xFFFFFFF006E11000,__ZTV10AppleARMIO
### Kext目录
该参数用于指向一个存放了Kext的目录，结构如下：
- *.kext
- kexts.txt
> *.kext为需要加入的kext
>
> kexts.txt用于指定需要添加的kext名称(不带.kext后缀)，或者是iOS内核缓存中Kext的包名，例如`BCM2837`和`com.apple.driver.AppleARMPlatform`。`System.kext`下的kext需要填写对应路径(不带.kext后缀)。
### 内核补丁
用于给iOS内核中Kext的指定部分进行补丁，补丁使用的是iOS内核缓存中的地址，格式如下：
```
# 注释
*地址
+补丁值
```
## 参考项目
- cocoahuke - [ioskextdump_ios10](https://github.com/cocoahuke/ioskextdump_ios10)