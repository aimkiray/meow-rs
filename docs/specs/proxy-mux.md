# proxy-mux: 连接多路复用（sing-mux + Xray Mux.Cool）

状态：sing-mux（smux / yamux / h2mux）与 **Xray Mux.Cool**（`protocol: muxcool`，
VLESS-only）全部实现，单测通过。互操作矩阵：
- sing-mux ↔ sing-box v1.13.18（VLESS 明文 / Trojan+TLS / Reality /
  Reality+Vision inbound 开 multiplex）双向打通；
- muxcool ↔ 本地 sing-box（明文 / Reality / Reality+Vision，TCP+UDP）打通；
- muxcool ↔ **真实 Xray 节点**（example-xray-node，VLESS Reality+Vision）
  打通——同一节点 sing-mux 无法互通（Xray 只认 Mux.Cool）。
（follow-up，源自 gap-analysis 的 mux 缺口）
参考实现：mihomo Alpha（adapter/outbound/singmux.go、listener/sing/sing.go）、
metacubex/sing-mux、sagernet/sing-mux、sagernet/smux（smux 帧格式）、
metacubex/sing v0.5.7（地址编解码）；Mux.Cool 参照 xray-core common/mux
（frame.go / writer.go / session.go）与 sing-vmess mux.go。

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

### 6. Xray Mux.Cool（`protocol: muxcool`，VLESS-only）

Mux.Cool 是 Xray 的帧多路复用协议（与 v2ray-plugin 的 mux 同源），与
sing-mux 完全无关：**没有** mux 请求头，会话信令就是 VLESS 请求头本身。

**信令**：会话连接的 VLESS 请求头 command = 0x03（CommandMux），**不写**
端口/地址（xray encoding.go::EncodeRequestHeader 对 CommandMux 跳过地址；
sing-vmess vless/protocol.go::ReadRequest 同样跳过解析）。VLESS 2 字节响应头
`[version, addons_len]` 依旧惰性消费（VlessConn 逻辑不变）。Vision 下请求头
随首个 mux 帧一起进首条 Vision 记录（VlessConn::new_mux_deferred，与 sing-mux
路径同理）。

**帧格式**（xray common/mux/frame.go，全大端）：

```text
meta_len   u16 BE    meta 块长度
meta:
  session_id u16 BE  流 id——客户端分配（从 1 递增），服务端原样回显
  status     u8      1=New 2=Keep 3=End 4=KeepAlive
  option     u8      bit1=Data, bit2=Error
  （New 帧，或携带 UDP 目标的 Keep 帧：）
    network u8       1=TCP 2=UDP
    port    u16 BE
    atype   u8       0x01 IPv4 | 0x02 domain | 0x03 IPv6
    address ...      VMess 地址布局（端口在前）
payload_len u16 BE   仅 option&Data 时存在
payload             payload_len 字节
```

End 帧无 payload_len；KeepAlive 帧用 sid=0（无绑定流）。服务端**永不主动开流**
（响应帧沿用客户端的 sid），New 帧的可选尾部 meta（xray 的 fullcone 来源信息、
UDP GlobalID）我们不发送，两端服务端都会丢弃多余 meta 字节。

**流语义**：
- TCP 流：New 帧（meta-only）开流 → Keep+Data 帧双向传数据（每帧 ≤ 8KiB，
  对齐 xray writer.go 的分块）→ End 帧（shutdown 或 drop 时发送，EndGuard
  保证恰好一次）。服务端 End → 干净 EOF；带 Error option → 错误。
- UDP 流：New 帧 network=UDP 开流；双向 Keep 帧 meta 携带**逐包目标地址**
  （与 sing-vmess serverMuxPacketConn 对齐），读侧解析回源地址，无地址的
  帧回退到流的绑定目标。
- 会话：读任务解复用（每流 32 深度有界通道，慢消费者反压整个会话——对齐
  xray 的阻塞 session buffer）；写侧单锁串行；30s KeepAlive（sid=0）保活；
  读任务/保活任务持 Weak 引用，池淘汰零流会话即整体回收。

**服务端兼容性**：Xray-core VLESS inbound（原生）；sing-box / mihomo 的
VLESS inbound（sing-vmess HandleMuxConnection，帧格式同源）。VMess 不支持
（Xray VMess 用 `v1.mux.cool` 魔法域名信令，与 sing-vmess 的 CommandMux
信令不同）。

## meow-rs 架构映射

```
crates/meow-proxy/src/mux/
  mod.rs        Protocol（+MuxCool）、MuxClient（会话池 + offer/offerNew + idle 清扫）
  request.rs    §2 sing-mux 请求头 encode/decode（含 padding）
  address.rs    §4 流请求编解码（flags + sing Socksaddr）
  smux.rs       smux 会话 + 流（sagernet fork 帧格式，自实现）
  yamux.rs      yamux 封装（依赖 libp2p 的 yamux crate）
  h2mux.rs      h2mux 会话 + 流（h2 crate：CONNECT 流 = 请求体/响应体双向）
  muxcool.rs    §6 Mux.Cool：帧编解码（纯函数）+ 会话 + TCP 流 + UDP PacketConn
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

- `protocol: smux|yamux|h2mux`（默认 h2mux）：服务端必须是 sing-box /
  mihomo 系（认识 `sp.mux.sing-box.arpa` 与 sing-mux 帧）。**Xray 服务器
  不兼容**——Xray 只认 Mux.Cool，此时请用 `protocol: muxcool`。
- `protocol: muxcool`（VLESS-only）：服务端为 Xray-core，或 sing-box /
  mihomo 的 VLESS inbound（其 sing-vmess 服务端原生处理 CommandMux，
  无需 inbound 配置）。Trojan 节点请勿使用。
- 两个协议族共用同一个 MuxClient 连接池与 min/max 约束，协议差异全部
  收敛在 SessionKind 各臂与 with_mux 的 dial 闭包内，适配层零分叉。

## 测试计划

1. 单测：request 头/padding 编解码；Socksaddr 编解码往返；smux 帧编解码
   （wire 字节断言）、SYN/FIN/PSH 状态机、大块分帧（内存 duplex 双端对打）；
   MuxClient 的 offer/offerNew/min-max 约束与并发上限（mock dialer）；
   yamux/h2mux 并发 open + 回显。
2. 集成（已完成，脚本见 target/e2e/mux-interop/）：
   - sing-mux：本地 sing-box v1.13.18 VLESS（明文）/Trojan（TLS）inbound
     开 multiplex，meow 经 h2mux/smux/yamux 三种协议 curl 本地 websrv 均
     200；6 路并发 curl 全部走同一条物理连接（sb.log 仅 1 次 inbound
     connection）。live_singbox_vless_probe 单测（#[ignore]）保留为可重复
     的互操作回归。
   - muxcool：同套 sing-box 入站（CommandMux 无需 inbound 配置）——明文
     VLESS（TCP 204/200 + UDP 回环）、Reality（204）、Reality+Vision
     （204 + UDP 回环，配置 meow-muxcool.yml / meow-reality-muxcool.yml /
     meow-rv-muxcool.yml）全部打通。
3. 真机：真实 Xray 节点（example-xray-node，VLESS Reality+Vision，配置
   meow-real-muxcool.yml）`protocol: muxcool` 打通 204（h2 + http/1.1），
   4 次连续连接复用同一物理会话（日志仅 1 次 VLESS 响应头消费）；同一节点
   sing-mux 失败（code=000）——印证两协议族互不兼容、按服务端选型。
