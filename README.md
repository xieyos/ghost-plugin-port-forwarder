# Port Forwarder · 端口转发

[中文](#中文) · [English](#english)

<!-- Screenshot: the management page inside Ghost's plugin center (docs/screenshot.png, to be added). -->

---

## 中文

一个 Ghost Proxifier 插件（基于 [Ghost Proxifier 插件 SDK](https://github.com/liliBestCoder/ghost-plugin-sdk)）：把本机端口转发到远端地址。每条规则一个监听端口（TCP 或 UDP），出口可以是**直连**、**Ghost 当前激活的上游节点**，或**指定的某个 Ghost 节点**。在 Ghost 的插件中心里管理，也能脱离 Ghost 独立运行（仅直连）。

灵感来自 [Jackarain/portmap](https://github.com/Jackarain/portmap)——一条 TCP 映射加一份配置文件；它自己的待办（SOCKS5、Web 管理、统计、多条映射）正是这里做的事，只不过代理这一半交给了 Ghost：**本插件里没有任何代理协议代码**。经节点的连接由 Ghost 建好、把连好的 socket 交给本插件（权限 `upstream.connect`），本插件只搬字节，节点的地址与凭据从不离开 Ghost。

### 要求

- Windows 10 1607 / Server 2016 或更新，x64。不需要 VC++ 运行库（静态链接）。
- 托管运行：Ghost Proxifier **≥ 1.2.1**（`upstream.connect` 从这一版开始；更旧的 Ghost 会整包拒绝本插件）。
- 独立运行：不需要 Ghost。

### 安装

- **插件中心**：上架之后，在 Ghost 的插件页「商店」里安装，启用时确认两项权限：`upstream.connect`（经你的节点开连接）与 `log.write`（写 Ghost 的应用日志）。
- **开发者模式本地安装**：在 Ghost 设置里打开插件开发者模式，然后在插件页用本地安装，选 Release 里的 `com.qtvz.xieyos.port-forwarder-<版本>.gpkg`。本地安装的插件不经注册表签名校验，只装你信任的包。

### 规则

| 字段 | 说明 |
|---|---|
| 名称 | 1–64 个字符 |
| 协议 | TCP 或 UDP |
| 监听 | `127.0.0.1`（默认，只有本机能连）、`0.0.0.0` 或本机某个 IPv4 地址；端口 1–65535 |
| 远端 | IPv4、IPv6（不带方括号）或主机名；端口 1–65535 |
| 出口 | 直连 / 跟随 Ghost 激活节点 / 指定节点 |
| 上限 | 每规则最大连接数（默认 128，1–1024）；UDP 空闲回收秒数（默认 60，5–3600） |

至多 64 条规则；启用的规则不能占同一个（协议, 地址, 端口），`0.0.0.0` 与同端口的任何地址冲突；转发到自己的监听地址会被拒绝。每条规则显示状态、活动/累计连接、上下行字节与最近一次错误。

### 出口与 UDP

- **直连**：本插件自己解析远端地址并连接。
- **经节点**：Ghost 经该节点建连接后交给本插件。**失败即关闭**：节点连不上、Ghost 拒绝或不可用时，客户端连接被关掉，**绝不回落直连**——否则流量会悄悄用你的真实地址出去。
- **UDP 经节点**要求该节点是 SOCKS5，且在 Ghost 里**已开启并验证 UDP 中继**（上游页的 UDP 开关）。节点不能中继 UDP 时，这条规则的数据报被丢弃并计数。
- 有些节点不能把 UDP 发往**主机名**：UDP 规则不通时，把远端换成 IP 地址试试。
- 托管但未授予 `upstream.connect`、Ghost 不可用、或独立运行时，经节点的规则**不监听**，状态分别是 `permission_missing` / `ghost_unavailable` / `needs_ghost`。

### 局域网暴露

监听 `0.0.0.0` 或局域网地址时，**局域网里任何人**都能经这个端口访问远端——经节点的规则等于把你的上游节点借给了他们。所以非回环地址必须在表单里勾选确认才能保存。

Windows 防火墙会在第一次监听时弹框：**只允许「专用网络」**。插件每次升级，安装路径（`plugins\<id>\<版本>\`）都会变，防火墙会再问一次。

### 独立运行

不经 Ghost 直接运行 `port-forwarder.exe`：

- 只支持直连规则；经节点的规则显示 `needs_ghost` 且不监听。
- 数据目录 `%LOCALAPPDATA%\com.qtvz.xieyos.port-forwarder\`（规则 `rules.json`、日志 `port-forwarder.log`，滚动 1 MB × 2）。
- `--data-dir <目录>` 换数据目录；`--no-browser` 不自动打开页面（地址打印在控制台）。
- 同一数据目录只能有一个实例。Ctrl+C 或页面上的「停止」退出。

### 安全

- 管理页只监听 `127.0.0.1`，地址带一个每次启动随机生成的 128 位路径前缀；校验 `Host`，写操作要求同源 `Origin` 与 `Content-Type: application/json`；CSP 只允许 Ghost 的页面嵌入它（独立运行时谁都不能嵌入）。
- 日志从不记录客户端地址与逐连接的目的地，也从不记录页面地址。
- 规则文件损坏时改名保留（`rules.json.corrupt-<时间>`），以空表启动，页面提示。

### 从源码构建

需要 Visual Studio 2022（「使用 C++ 的桌面开发」）与 CMake ≥ 3.20：

```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

产物 `build/Release/port-forwarder.exe`。版本号只有一个来源：`manifest.json` 的 `version`。打包检查（`test_pack`）需要 Python ≥ 3.9 与一份 [ghost-plugin-sdk](https://github.com/liliBestCoder/ghost-plugin-sdk) 检出（默认在本仓库旁边的 `../ghost-plugin-sdk`，或设环境变量 `GHOST_PLUGIN_SDK` / `-DPF_GHOST_SDK_DIR=`）；缺了就显示 Skipped。检出是 git 仓库时，它的 HEAD 必须是 `.github/workflows/ci.yml` 里钉住的 `SDK_REF`，否则检查失败。

### 发版（维护者）

推一个 `v<版本>` 标签，`.github/workflows/release.yml` 构建、测试、用 SDK 的 `gpkg.py` 打包与签名，并建 GitHub Release（三个资产：`ghost-plugin.json`、`ghost-plugin.json.sig`、`.gpkg`）。一次性准备：

1. `python <sdk>/tools/plugin/gpkg.py keygen --out <仓库之外的目录>`；
2. 把 `dev-public.b64` 提交到仓库根（工作流用它复核签名；构建开始前先检查它存在且是 64 字节的公钥，缺了直接失败）；
3. 把 `dev-private.pem` 的全部内容存成仓库 secret `GHOST_DEV_KEY_PEM`，本地那份离线保管。

私钥永远不进仓库（`.gitignore` 挡着 `*.pem`、`*.key`、`.keys/`）。

### 许可

MIT，见 [LICENSE](LICENSE)。第三方：nlohmann/json（MIT），见 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)。

---

## English

A Ghost Proxifier plugin (built on the [Ghost Proxifier plugin SDK](https://github.com/liliBestCoder/ghost-plugin-sdk)) that forwards local ports to remote hosts. Each rule is one listening port (TCP or UDP); its egress is **direct**, **Ghost's active upstream node**, or **a chosen Ghost node**. You manage it from Ghost's plugin center, or run it on its own without Ghost (direct only).

Inspired by [Jackarain/portmap](https://github.com/Jackarain/portmap) -- one TCP mapping and a config file; its own to-do list (SOCKS5, web management, statistics, many mappings) is what this plugin does, except that the proxy half is Ghost's: **there is no proxy protocol code in this plugin**. For a via-node rule Ghost connects through the node and hands the connected socket over (permission `upstream.connect`); the plugin only moves bytes, and the node's address and credentials never leave Ghost.

### Requirements

- Windows 10 1607 / Server 2016 or later, x64. No Visual C++ redistributable needed (static CRT).
- Hosted: Ghost Proxifier **1.2.1 or later** (`upstream.connect` first shipped there; an older Ghost refuses the package).
- Standalone: no Ghost needed.

### Install

- **Plugin center**: once listed, install it from the Store tab of Ghost's plugins page and confirm the two permissions when enabling it: `upstream.connect` (open connections through your nodes) and `log.write` (write to Ghost's application log).
- **Developer mode, local install**: turn on plugin developer mode in Ghost's settings, then use local install on the plugins page and pick `com.qtvz.xieyos.port-forwarder-<version>.gpkg` from a release. A local install skips the registry's signature checks -- only install packages you trust.

### Rules

| Field | Meaning |
|---|---|
| Name | 1-64 characters |
| Protocol | TCP or UDP |
| Listen | `127.0.0.1` (default: this machine only), `0.0.0.0` or one of this machine's IPv4 addresses; port 1-65535 |
| Remote | IPv4, IPv6 (no brackets) or a host name; port 1-65535 |
| Egress | Direct / follow Ghost's active node / a chosen node |
| Limits | Max connections per rule (default 128, 1-1024); UDP idle timeout in seconds (default 60, 5-3600) |

At most 64 rules; two enabled rules cannot share a (protocol, address, port), `0.0.0.0` conflicts with any address on the same port, and a rule that forwards to its own listener is refused. Each rule shows its status, active/total connections, bytes up/down and its last error.

### Egress and UDP

- **Direct**: the plugin resolves the remote host and connects itself.
- **Through a node**: Ghost connects through the node and hands the connection over. **Fail closed**: when the node is unreachable or Ghost refuses or is unavailable, the client connection is closed -- **never retried directly**, which would quietly send the traffic from your real address.
- **UDP through a node** needs a SOCKS5 node whose **UDP relay is enabled and verified in Ghost** (the UDP switch on the upstream page). If the node cannot relay, the rule's datagrams are dropped and counted.
- Some nodes cannot relay UDP to a **host name**: if a UDP rule gets nothing back, try an IP address as the remote.
- Hosted without `upstream.connect`, with Ghost unavailable, or standalone, a via-node rule **does not listen**; its status is `permission_missing`, `ghost_unavailable` or `needs_ghost`.

### LAN exposure

Listening on `0.0.0.0` or a LAN address lets **anyone on the network** reach the remote through that port -- for a via-node rule, that lends them your upstream node. A non-loopback address therefore cannot be saved without ticking the acknowledgement in the form.

Windows Firewall asks the first time the plugin listens: **allow private networks only**. Every upgrade changes the install path (`plugins\<id>\<version>\`), so the firewall asks again.

### Standalone

Run `port-forwarder.exe` without Ghost:

- Direct rules only; via-node rules show `needs_ghost` and do not listen.
- Data directory `%LOCALAPPDATA%\com.qtvz.xieyos.port-forwarder\` (rules in `rules.json`, log in `port-forwarder.log`, rolled at 1 MB x 2).
- `--data-dir <dir>` uses another data directory; `--no-browser` does not open the page (the address is printed on the console).
- One instance per data directory. Ctrl+C or the page's Stop button ends it.

### Security

- The management page listens on `127.0.0.1` only, under a random 128-bit path prefix made at every start; it checks `Host`, requires a same-origin `Origin` and `Content-Type: application/json` on writes, and its CSP lets only Ghost's page frame it (nobody, standalone).
- The log never records client addresses, per-connection destinations, or the page's address.
- A damaged rules file is kept under a new name (`rules.json.corrupt-<time>`); the plugin starts with no rules and the page says so.

### Building from source

Visual Studio 2022 ("Desktop development with C++") and CMake 3.20 or later:

```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The result is `build/Release/port-forwarder.exe`. The version has one source: `version` in `manifest.json`. The packing check (`test_pack`) needs Python 3.9+ and a checkout of [ghost-plugin-sdk](https://github.com/liliBestCoder/ghost-plugin-sdk) (by default `../ghost-plugin-sdk` next to this repository, or set `GHOST_PLUGIN_SDK` / `-DPF_GHOST_SDK_DIR=`); without them it shows as Skipped. When the checkout is a git repository, its HEAD must be the `SDK_REF` pinned in `.github/workflows/ci.yml`, or the check fails.

### Releasing (maintainer)

Push a `v<version>` tag: `.github/workflows/release.yml` builds, tests, packs and signs with the SDK's `gpkg.py`, and creates the GitHub Release with three assets (`ghost-plugin.json`, `ghost-plugin.json.sig`, the `.gpkg`). One-time setup:

1. `python <sdk>/tools/plugin/gpkg.py keygen --out <a directory outside the repository>`;
2. commit `dev-public.b64` at the repository root (the workflow verifies the signature with it, and checks before building that it exists and holds a 64-byte public key);
3. store the whole of `dev-private.pem` as the repository secret `GHOST_DEV_KEY_PEM`, and keep the local copy offline.

The private key never goes into the repository (`.gitignore` blocks `*.pem`, `*.key`, `.keys/`).

### License

MIT, see [LICENSE](LICENSE). Third party: nlohmann/json (MIT), see [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
