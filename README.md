# Pyscanner简单用法解析

Pyscanner是一个基于python 2.7的简易端口扫描工具

## 目录

- [背景](#背景)
- [安装](#安装)
- [使用说明](#使用说明)


## 背景

算是工作中的第一次编程吧，设计一个多线程、适合大范围的IP扫描的python程序。
其中考虑到实际应用中会存在断点问题，设计了中断处理，并且能够从中断处恢复扫描状态。

## 安装

运行环境是`python 2.7`

```
git clone https://github.com/ev3rN1ght/pyscanner.git
```

## 使用说明

### 扫描单个IP

```
python scanner.py ip addr port
```

`ip` 为固定指令，进入单个IP扫描子解析器  
`addr`为具体IP地址，例：`8.8.8.8`  
`port`为端口号或者端口范围，端口号例：`22`，`80`  端口范围示例：`1-10000`

### 从文件中读取IP列表进行扫描

```
python scanner.py file iplist.txt
```

`file`为固定指令，进入读取文件的子解析器  
`iplist.txt`是IP地址列表文件  
文件中规定格式为每行列出一个地址  
其中IP地址在前，端口号在后  
IP地址和端口号用空格分隔
端口号支持端口范围

### 从中断日志中读取并继续扫描

```
python scanner.py continue interrupt.txt
```

`continue`为固定指令，进入恢复扫描的子解析器  
`iplist.txt`是之前中断的日志文件  
