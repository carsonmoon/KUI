
# 🚀 KUI 群控VPS网关

<div align="center">

![Cloudflare Pages](https://img.shields.io/badge/Deployed_on-Cloudflare_Pages-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Vue.js](https://img.shields.io/badge/Frontend-Vue3-4FC08D?style=for-the-badge&logo=vue.js&logoColor=white)
![Python](https://img.shields.io/badge/Agent-Python3-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**下一代轻量级、全协议、零运维的 Serverless VPS 聚合管理与节点下发网关。**

[部署指南](#-闪电部署) • [核心特性](#-核心黑科技) • [探针架构](#-硬核原生探针) • [UI 预览](#-果味高颜面板)

</div>

---

## 💡 项目初衷

**KUI** 诞生于极致的 Serverless 理念：**将主控端完全托管于 Cloudflare 边缘网络，VPS 仅需运行极致轻量的纯 Python 探针。** 

这不仅意味着**主控端永远免费、永不宕机、且极度隐蔽**，更意味着你可以通过一个绝美的可视化面板，轻松驾驭多台机器上的 7 大前沿代理协议。

## ✨ 核心黑科技

- ☁️ **100% Serverless 主控**：基于 Cloudflare Pages/Workers + D1 数据库。**零配置部署**，无需手动建表，首次登录面板自动完成数据库初始化与热升级。
- 🔮 **全协议制霸 (7-in-1)**：完美支持 `VLESS`、`Reality`、`Hysteria 2`、`TUIC v5`、`Socks5` 以及 `Dokodemo-door (内部链式/公网转发)`。面板一键下发，VPS 探针自动拉取并重载 Sing-box。
- ⚡️ **VLESS-Argo 全自动穿透救砖**：遇到纯 IPV6 或被墙机器？下发 Argo 协议后，探针将在后台静默下载 `cloudflared`，自动建立内网穿透隧道，并在 15 秒内疯狂抓取 `.trycloudflare.com` 临时域名回传至面板！
- 🛡️ **双轨制与多租户隔离**：
  - **军工级鉴权**：动态 HMAC-SHA256 签名，5 分钟时间戳防重放攻击。
  - **多租户管理**：支持给不同用户分配专属节点、流量配额 (GB) 及到期时间限制。
- 🤖 **Telegram 全自动巡检**：利用 CF 定时触发器 (Cron)，节点掉线超过 3 分钟自动推送 TG 告警。

## 📊 硬核原生探针 (Agent)

KUI 的 VPS 探针 `agent.py` 彻底抛弃了依赖繁杂的 Bash 命令，采用**纯 Python 读取 Linux 内核文件** (`/proc/stat`, `/proc/meminfo`, `/proc/net/dev` 等) 的极致方案：

- **绝对兼容**：完美适配 Debian, Ubuntu, CentOS, Alpine 等所有主流发行版，杜绝 `awk` 或 `df` 命令缺失导致的报错。
- **四宫格高阶监控**：不仅监控 CPU 和 内存，还能精准抓取**磁盘使用率 (Disk)、系统负载 (Load)、精准运行时长 (Uptime) 以及毫秒级双向网络速率 (Up/Down Speed)**。
- **自动签发证书**：下发 Hysteria2 或 TUIC 时，探针全自动调用 OpenSSL 签发域名证书，全程无感。

## 🎨 果味高颜面板 (Apple Glassmorphism)

告别土味后台，KUI 采用了基于 TailwindCSS 构建的极致拟物毛玻璃 UI：
- 仪表盘大厅实时展示全网机器在线状态与聚合大流量。
- 丝滑的动画过渡与 Echarts 7 天流量趋势可视化。
- 动态状态回显（例如 Argo 穿透时的“⏳ 正在等待回传”流光提示）。

---

## 🚀 闪电部署

### Step 1: 准备 Cloudflare D1 数据库
1. 登录 Cloudflare 控制台，进入 `Workers & Pages` -> `D1`。
2. 创建一个全新的 D1 数据库，命名为 `kui-db`（无需在控制台输入任何 SQL 语句建表！）。

### Step 2: 部署主控端 (Cloudflare Pages)
1. Fork 本仓库。
2. 在 Cloudflare Pages 中连接你的 Github 仓库进行部署。
3. **关键绑定**：
   - 在项目 `设置` -> `函数` -> `D1 数据库绑定` 中，将变量名设为 `DB`，并选择你刚才创建的 `kui-db`。
   - 在 `环境变量` 中添加以下变量：
     - `ADMIN_USERNAME`: 你的管理员账号（默认 `admin`）
     - `ADMIN_PASSWORD`: 你的管理员密码
     - *(可选)* `TG_BOT_TOKEN`: 你的 Telegram Bot Token
     - *(可选)* `TG_CHAT_ID`: 接收告警的 TG 频道或用户 ID

### Step 3: 零配置初始化
访问你的 Pages 域名，输入设置的账号密码登入。
**系统将瞬间在后台为你全自动建表并完成所有初始化配置！** 享受属于你的 KUI 面板吧。

---

## 💻 探针接入指南

在 KUI 面板的“服务器与节点”页面，点击**接入机器**。系统会为你生成一串专属的终端部署指令。
复制该指令到你的 VPS 终端执行即可：

```bash
# 面板生成的指令示例
bash <(curl -sL https://raw.githubusercontent.com/你的用户名/KUI/main/vps/kui.sh) --api "你的面板域名" --ip "VPS的公网IP" --token "你的加密Token"
```

探针部署完毕后，面板上的该机器指示灯将在 1 分钟内转为绿色 🟢，并点亮所有硬件监控数据！

## ⚠️ 免责声明

本项目仅供编程学习与网络网络架构研究使用。请严格遵守您所在国家或地区的法律法规，请勿用于任何非法用途。开发者不对使用本项目造成的任何后果负责。

## 📄 License
[MIT](LICENSE) © Your Name / KUI Contributors
