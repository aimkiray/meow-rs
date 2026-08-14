# proxy-mux: sing-mux 兼容的连接多路复用（mihomo 方式）

状态：smux / yamux / h2mux 全部实现，单测通过，并已与真实 sing-box v1.13.18
（VLESS 明文 / Trojan+TLS inbound 开 multiplex）双向打通（h2mux 为 mihomo 默认
协议）。真机延迟对比见 §测试计划第 3 条。
（follow-up，源自 gap-analysis 的 mux 缺口）
参考实现：mihomo Alpha（adapter/outbound/singmux.go、listener/sing/sing.go）、
metacubex/sing-mux、sagernet/sing-mux、sagernet/smux（smux 帧格式）、
metacubex/sing v0.5.7（地址编解码）

## 目标

按 mihomo 的方式实现真 mux：对 VLESS/Trojan 出站提供
`mux: {enabled, protocol, max-connections, min-streams, max-streams, padding, statistic, only-tcp}`
（对齐 SingMuxOption），在**单条节点连接**上多路复用多条逻辑流，消除每个新隧道流
都要付一遍节点 TCP+TLS+协议握手的开销（当前实测 500-700ms/新连接 @140ms RTT）。

## 线上协议（已从源码逐字段确认）

### 1. 物理连接建立（VLESS）
1. 客户端 TCP+TLS 到节点，发送 VLESS 请求头，**目标地址 = 保留 mux 域名**
   `sp.mux.sing-box.arpa:444`（FQDN，命令 = CommandTCP）。普通请求头格式不变。
2. 紧跟请求头之后**立即**写 mux 请求头（见 §2，与首请求同一批写）。
3. 服务器识别 FQDN → 切入 mux 服务；VLESS 的 2 字节响应头
   （`[version, addons_len]`）由服务器**惰性附加在第一次下行写的头部**，
   客户端首次读时先剥掉（meow-rs 的 `VlessConn` 已有 `response_pending`
   惰性消费逻辑，天然兼容）。

### 2. Mux 请求头（协议版本协商）
| 字段 | 长度 | 说明 |
|---|---|---|
| version | u8 | 0 或 1 |
| protocol | u8 | 0=smux, 1=yamux, 2=h2mux（mihomo 默认 h2mux） |
| padding | u8 | 仅 version==1 存在；1=启用 |
| padding_len | u16 BE | 仅 padding=1；值 = 256 + rand(512) |
| padding bytes | n | 随机填充 |

### 3. 会话（每物理连接一个，按 protocol 选择实现）
- **smux**：注意——sing-mux 用的是 **sagernet/smux fork**，帧格式与上游
  xtaci 不同：[ver=1][cmd][len u16 LE][stream_id u32 LE][data]（8 字节头、
  小端）。cmd: SYN=0, FIN=1, PSH=2, NOP=3（UPD=4 仅 v2 存在）。v1 **没有
  窗口更新流控**——写侧直接按 MaxFrameSize=32768 分帧发送（u16 长度上限）。
  配置 = smux.DefaultConfig() + KeepAliveDisabled=true（Version=1、
  MaxFrameSize=32768、MaxStreamBuffer=64KiB、MaxReceiveBuffer=4MiB）。
- **yamux**：hashicorp yamux（libp2p rust-yamux 与其线上互通）；
  StreamClose/OpenTimeout = 5s。
- **h2mux**（mihomo 默认）：HTTP/2 之上 sing 自定义（sing-mux/h2mux.go）。
  每条流 = 一个 CONNECT 请求到 https://localhost（无 :scheme/:path），
  请求体 DATA 帧 = 客户端→服务端，响应体 DATA 帧 = 服务端→客户端。
  **服务端惰性 flush 200**：只有首次响应体写入时才把 200 HEADERS 刷上线，
  所以客户端**不能阻塞等 200**——sing-mux 用 lateHTTPConn（写侧立即可用，
  读侧等 setup）——meow-rs 同样在首读时惰性解析响应，5s（TCPTimeout）超时。
  流结束时 sing-box 发 RST_STREAM(NO_ERROR)，按干净 EOF 处理（Go 客户端
  同样映射为 io.EOF）。空闲超时 30s（h2mux.go idleTimeout）。

### 4. 流内寻址（StreamRequest / StreamResponse）
客户端打开每条流后，第一条写是**流请求**（protocol.go EncodeStreamRequest）：
[flags u16 BE][type u8][addr][port u16 BE]，flags=0 表示 TCP
（flagUDP=1 用于 UDP 流）。Socksaddr type：0x01=IPv4(4B)、0x03=FQDN(len u8
+ bytes)、0x04=IPv6(16B)。服务器读地址 → 按流建立到真实目标的连接。

**每条流的第一条下行写带状态字节**（serverConn.Write）：[status u8]，
0=success；1=error 后跟 varbin 长度前缀的错误消息。客户端首读时先剥掉
状态字节（sing-mux clientConn.readResponse）；meow-rs 在 MuxStream 层统一
处理（三种协议一致）。

**UDP 流**：flags 置 flagUDP(1) 的流是 UDP 流，绑定流请求中的目标地址；
之后双向都是 [len u16 BE][data] 数据报帧（与 meow VLESS UDP-over-TCP
同款帧），无逐包地址。服务端以 serverPacketConn 处理。meow-rs 的
`MuxPacketConn` 实现该封装；`only-tcp: true` 时 UDP 走原明文路径。
`statistic`/`brutal-opts` 字段暂不支持（解析时各打一条 warn 忽略，
brutal 上游仅 Linux）。

### 5. 客户端会话管理（对齐 sing-mux client.go）
- `openStream`：从现存会话中选 `CanTakeNewRequest && NumStreams 最小` 的会话开流；
  无可用会话 → `offerNew`（新物理连接 + 握手 + 会话）。
- 约束：maxConnections>0 时按连接数/每连接 minStreams 决定；否则按全局 maxStreams。
- 连接失败/会话关闭 → 最多重试 2 次；空闲会话按 idle 超时关闭（默认 60s，
  sing-mux Service 的 IdleTimeout）。
- padding 模式下 version=1；TCPTimeout=5s 限制建连。

## meow-rs 架构映射

```
crates/meow-proxy/src/mux/
  mod.rs        MuxOption、MuxClient（会话池 + offer/offerNew + idle 清扫）
  request.rs    §2 mux 请求头 encode/decode（含 padding）
  address.rs    §4 流请求编解码（flags + sing Socksaddr）
  smux.rs       smux 会话 + 流（sagernet fork 帧格式，自实现）
  yamux.rs      yamux 封装（依赖 libp2p 的 yamux crate）
  h2mux.rs      h2mux 会话 + 流（h2 crate：CONNECT 流 = 请求体/响应体双向）
  packet.rs     MuxPacketConn：UDP 流（flagUDP + [len u16 BE][data] 数据报帧）
  stream.rs     MuxStreamConn: ProxyConn 封装（!Unpin 内流的 pin-projection，
                参考 anytls AnytlsConn 的模式）
```

- 接入点：`vless_adapter::dial_tcp` 与 `trojan::dial_tcp`——mux 启用时改为
  `mux_client.open_stream(dest)` 而不是新建连接；建连函数 `mux_dialer` 复用
  现有 `dial_stream`/`open_tls_with_header`，目标地址替换为
  `sp.mux.sing-box.arpa:444`。
- 配置解析：解析完整 mux 块，默认 protocol=h2mux 与 mihomo 对齐；
  smux/yamux/h2mux 均实现；未知 protocol 按 meow 的 warn+skip 语义拒绝该
  节点（mihomo 对同样输入是硬错误）。
- 构建门控：`mux` Cargo feature（meow-proxy/meow-config/meow-app，默认开启，
  `minimal` 排除）。无 mux 构建读到 enabled mux 块会打 warn 提示已忽略。
- 健康检查/URLTest：走 mux 流的延迟探测天然复用同一会话。

## 互操作边界（重要）

- 服务端必须是 sing-box / mihomo 系（认识 `sp.mux.sing-box.arpa` 与
  smux/yamux/h2mux）。**Xray 服务器不兼容**（Xray 只支持 Mux.Cool/XMUX）。
- mihomo 兼容服务端：sing-box 的 VLESS/Trojan inbound 开 `mux` 后即互通。

## 测试计划

1. 单测：request 头/padding 编解码；Socksaddr 编解码往返；smux 帧编解码
   （wire 字节断言）、SYN/FIN/PSH 状态机、大块分帧（内存 duplex 双端对打）；
   MuxClient 的 offer/offerNew/min-max 约束与并发上限（mock dialer）；
   yamux/h2mux 并发 open + 回显。
2. 集成（已完成，脚本见 target/e2e/mux-interop/）：本地 sing-box v1.13.18
   VLESS（明文）/Trojan（TLS）inbound 开 multiplex，meow 经 h2mux/smux/
   yamux 三种协议 curl 本地 websrv 均 200；6 路并发 curl 全部走同一条物理
   连接（sb.log 仅 1 次 inbound connection）。live_singbox_vless_probe
   单测（#[ignore]）保留为可重复的互操作回归。
3. 真机：真实 VLESS 节点开 mux 前后，首请求/新连接延迟对比
   （复用 mockdns/websrv 与测速方法）。
