# 🚀 FreeSub - 免费多协议节点自动聚合与测活池

> 🤖 **自动更新时间**：`2026-09-09 11:06:24 UTC`  
> 🛡️ **节点经过双重防断流探测、抗欺诈拦截与真实落地 Egress IP 归类**。

---

### 🌟 全量测活节点订阅（全协议合并）

| 客户端类型 | 有效节点数 | ⚡ 免翻 CDN 直链 | 🌐 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| **🐱 Clash / Mihomo (YAML)** | **119** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/clash.yaml) | [🌐 Raw 订阅](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/clash.yaml) |
| **⚡ V2RayN (Base64 格式)** | **119** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/v2ray.txt) | [🌐 Raw 订阅](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/v2ray.txt) |
| **📦 sing-box (JSON 格式)** | **119** | [⚡ CDN 订阅](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/singbox.json) | [🌐 Raw 订阅](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/singbox.json) |

---

### 🏠 按照家宽分类节点订阅（住宅 IP 专区）

> 经 MaxMind ASN 离线库与核心运营商白名单严格甄别，剔除数据中心及云厂商，保留民用住宅宽带。当前可用家宽节点：**0** 个。

| 家宽地区 | 数量 | V2RayN 订阅 | Clash 订阅 | sing-box 订阅 |
| :--- | :---: | :--- | :--- | :--- |
| <nobr>暂无家宽</nobr> | 0 | - | - | - |

---

### 🌍 按照国家/地区分类节点订阅（落地出口）

| 地区代码 | 数量 | V2RayN 订阅 | Clash 订阅 | sing-box 订阅 |
| :--- | :---: | :--- | :--- | :--- |
| <nobr><img src="https://flagcdn.com/20x15/us.png" width="20" height="15" alt="US"> US 美国</nobr> | 119 | <nobr>[⚡CDN](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/by-country/US.txt) · [🌐Raw](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/by-country/US.txt)</nobr> | <nobr>[⚡CDN](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/by-country/clash-US.yaml) · [🌐Raw](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/by-country/clash-US.yaml)</nobr> | <nobr>[⚡CDN](https://fastly.jsdelivr.net/gh/hezhanleiok/freesub@main/output/by-country/singbox-US.json) · [🌐Raw](https://raw.githubusercontent.com/hezhanleiok/freesub/main/output/by-country/singbox-US.json)</nobr> |

---

### 📌 订阅使用提示
1. **CDN 直链**：适合国内网络直连拉取，已配置 jsDelivr 全球加速节点。
2. **Raw 直链**：GitHub 官方源文件，适合挂代理环境下获取实时配置。
