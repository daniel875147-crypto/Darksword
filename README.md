## iOS Safari 沙盒逃脱及后渗透 C2 框架

> ⚠️ **本代码库仅供授权的安全研究、CTF竞赛和教学演示使用。未经授权对任何设备进行测试均属违法行为。作者对此不承担任何责任。**

### 📞 商业支持和完整项目访问权限
**此仓库已剔除payload以及Pe阶段代码。完整代码不免费提供**
如果您需要完整代码，请联系：

| Contact        | Address                  |
| -------------- | ------------------------ |
| **Telegram**   | <https://t.me/Hogphoto> |

- **定价：588 USDT**
- **⚠️仅包含JS代码，不提供后端代码，需自行编写后台代码**

受影响设备
iOS 18.4 - 18.7.2 | A17 Pro / A18 / A18 Pro | iPhone 15 Pro/Pro Max, iPhone 16 全系
iOS 18.4 - 18.7.2 | A17 Pro / A18 | iPhone 15 Pro 系列, iPhone 16 系列
iOS 13.0 - 17.2.1 | A12 - A16 | iPhone XS - iPhone 15 系列

不受影响的设备：
- iOS < 13.0（漏洞不存在）
- iOS > 18.7.3（已修补）
- A11 及以下芯片（iPhone X 及更早）

## 自动收割数据

植入成功后自动收割以下数据（全部自动，无需操作）：

| iOS Keychain | 全部 keychain 条目（密码/证书/token） | ✅ |
|------|---------|------|
| 钱包文件 | 加密钱包文件（vault/keystore/seco 等） | ✅ |
| 加密货币助记词 | 明文助记词（在内存/keychain 中） | ✅ |
| 通讯录 | 全部联系人 | ✅ |
| 短信 | 短信记录（含验证码） | ✅ |
| 照片 | 相册照片 | ✅ |
| 浏览器数据 | Safari 历史/Cookie/保存的密码 | ✅ |
| WhatsApp | 聊天记录（如安装） | ✅ |
| Telegram | 聊天记录+会话（如安装） | ✅ |
| 通话记录 | 通话历史 | ✅ |
| WiFi 密码 | 已保存的 WiFi 密码 | ✅ |
| 设备信息 | UDID/序列号/型号/iOS版本 | ✅ |
| 位置信息 | GPS 坐标 | ✅ |
| 安装应用列表 | 全部已安装 App | ✅ |
| 剪贴板 | 剪贴板内容 | ✅ |

## 钱包收割明细

### 明文直接提取（无需解密）

| 钱包 | 提取方式 | 说明 |
|------|---------|------|
| Bitpie | keychain | 助记词直接在 keychain 中 |
| Trust Wallet | keychain | 部分版本明文 |
| Uniswap Wallet | keychain | 明文助记词 |
| Phantom | keychain | Solana 助记词明文 |
| Solflare | keychain | 明文 |
| MyTonWallet | keychain | TON 助记词明文 |
| Tonkeeper | keychain | 明文 |
| Coin98 | RN 存储 | base64 编码（自动解码） |
| Coinbase Wallet | keychain | 明文 |
| Binance Wallet | keychain | 明文 |
| MathWallet | keychain | 明文 |

### 需要密码解密（自动配对 keychain 密码）

| 钱包 | 加密方式 | 解密引擎 |
|------|---------|---------|
| MetaMask | AES-256-GCM + PBKDF2 | ✅ 自动 |
| Trust Wallet (旧版) | Keystore V3 (scrypt + AES-CTR) | ✅ 自动 |
| TronLink | Keystore V3 | ✅ 自动 |
| imToken V3 | PBKDF2 + AES-128-CTR | ✅ 自动 |
| imToken V2 | PBKDF2 + AES-256-CBC | ✅ 自动 |
| Bitget | iOS plist + 加密 | ✅ 自动 |
| OKX Wallet | AES-256-GCM + PBKDF2 | ✅ 自动 |
| Exodus | AES-256-CBC/GCM + PBKDF2-SHA512 | ✅ 自动 |
| Tonhub | MMKV 二进制 + 加密 | ✅ 自动 |
| Ronin Wallet | Keystore V3 + MAC 验证 | ✅ 自动 |

### 解密引擎

**全自动解密流水线（无需手动输入密码）：**

收割器上报 keychain + 加密钱包

         ↓
         
解析器自动暂存到 encrypted_wallets (status=pending)

         ↓
         
后台调度器（每 10 秒扫描）
  → 从同设备 keychain 提取密码候选
  → 逐一尝试解密（支持 6 种加密格式）
  → 成功: 助记词写入 + status=decrypted
  
         ↓
         
keychain_monitor 发现新密码 → 下一轮自动重试

         ↓
         
BIP39 内存扫描 → 直接抓明文助记词（跳过解密）

         ↓
         
面板 10 秒自动刷新 → 显示解密结果

**支持的加密格式：**

| 格式 | 算法 | 对应钱包 |
|------|------|---------|
| MetaMask Vault | PBKDF2 + AES-256-GCM | MetaMask |
| Keystore V3 | scrypt/PBKDF2 + AES-128-CTR + MAC | Trust/TronLink/Ronin |
| imToken V3 | PBKDF2 + AES-128-CTR | imToken |
| imToken V2 CBC | PBKDF2 + AES-256-CBC | imToken 旧版 |
| iOS Plist | plistlib 解析 + 嵌套提取 | Bitget |
| OKX | PBKDF2 + AES-256-GCM | OKX |
| Exodus .seco | PBKDF2-SHA512 + AES-CBC/GCM (5种组合) | Exodus |
| MMKV Binary | MMKV 格式解析 + 字符串提取 | Tonhub |
| Ronin | Keystore V3 + HMAC-SHA256 MAC | Ronin/Axie |

### 命令模板（32 种）

**信息收集：** 获取系统信息 / 获取网络信息 / 获取进程列表 / 获取应用列表 / 读取剪贴板 / 网络探测

**数据窃取：** 窃取Keychain / 窃取WiFi密码 / 窃取通讯录 / 窃取短信 / 窃取照片 / 窃取邮件 / 窃取备忘录 / 窃取iCloud / 收集WhatsApp / 收集Telegram / 收集加密钱包 / 收集浏览器 / 收集媒体 / 收集短信

**文件操作：** 列出目录 / 搜索文件 / SQLite查询

**权限提升：** 越狱检测 / 漏洞利用 / Root提权

**远程控制：** 截屏 / 拍照(前置) / 拍照(后置) / 录音 / 杀进程

**自定义：** 执行Shell命令 / 执行JavaScript / 读取文件 / 重载攻击链


## 📜 开源协议与免责

本仓库代码以 **MIT** 协议发布，但：

- **不包含**真实Payload以及PE代码
- **不提供**针对真实设备的攻击能力
- **不承担**任何因不当使用造成的法律后果
- 下载即视为已阅读并同意本 README 的法律声明

完整利用链（含真实 payload 与版本适配）需联系作者获取：

| 联系方式         | 地址                     | 价格        |
| ------------ | ---------------------- | --------- |
| **Telegram** | <https://t.me/Hogphoto> | 588 USDT |

***

## ⚠️ 最终警告

> **下载后 24 小时内请删除。**
>
> 本项目仅用于授权安全研究、CTF 竞赛与教学演示。未经授权对任何设备进行测试均属违法行为。作者不提供、不销售任何针对真实受害者的攻击服务。
>
> **合法使用，自负其责。**

***
