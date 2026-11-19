# Ant Browser 账号登录态离线迁移工具（零耦合独立版）

本工具位于 `tools/session-migrator/`，自带独立的 `go.mod`，**与主项目代码无任何导入或构建耦合**。编译后的 `ant-session-migrator.exe` 是单文件免依赖程序，可直接拷贝到另一台仅安装了 **Ant Browser 正式版** 或使用 **`.\bat\dev.bat`** 的 Windows 电脑上运行。

## 核心原理（为什么干净且不触发 Google 风控）

1. **全程离线重加密，零启动浏览器、零网络发包**
   - **导出（源电脑）**：要求目标实例已停止，离线读取实例的 `Local State` 并调用本机 Windows DPAPI 解出 32 字节 AES-256-GCM 主密钥，直接解密 `Default/Network/Cookies`（完整校验并保留 Chromium schema v24 的全部 20 列原始字段与时间戳），打包成 `.antsess` 文件（支持 `scrypt + AES-256-GCM` 密码加密，也支持自用不加密）。
   - **导入（目标电脑）**：离线复用（或为新实例生成）目标电脑本地 Windows DPAPI 保护的 `Local State` 密钥，将全部 Cookie 按 Chromium v24 + `v10` AES-256-GCM + `SHA256(host_key)` 规范重新加密后原子写入 `Default/Network/Cookies`，并写入 `NetworkDataMigrated` 检查点标记。
2. **默认只迁登录态，可选最干净的「代理 IP」与「核心指纹」同步**
   - **默认必迁（登录态）**：`Default/Network/Cookies` + `Default/Local Storage/leveldb` + `Default/Session Storage`（可选 `--cookies-only` 或 `--include-indexeddb`）。
   - **可选迁移核心指纹（`--include-fingerprint` / `--sync-fingerprint`）**：仅迁移实例的 `fingerprint_args`（若源实例未显式写 `--fingerprint=`，会自动物化出与 Ant Browser 启动期一致的确定性种子，确保跨机匹配不同实例 ID 时指纹仍完全一致）。
   - **可选迁移代理 IP（`--include-proxy` / `--sync-proxy`）**：仅迁移被导出实例**实际引用**的最小代理节点（`proxy_config`、`preferred_kernel`、`dns_servers`、`group_name`）与绑定关系；**绝不导出**未引用节点、订阅链接（`source_url`）或历史测速/IP 健康缓存；导入时按 `proxy_config` 自动去重复用，**绝不覆盖**目标机已有的不同代理节点；所有代理凭据均放在内层加密载荷中，绝不写入公开 `manifest.json`。
   - **绝不触碰**：`config.yaml`、插件、书签、分组、标签、历史记录、缓存、`Preferences`、`Secure Preferences`。
3. **默认不改目标 `app.db`，按需安全写入并自动备份**
   - 默认只匹配目标机已有实例（按 `profile_id` 优先、`profile_name` 兜底），严格只读目标 `app.db`。
   - 当启用 `--create-missing`、`--sync-fingerprint` 或 `--sync-proxy` 需要写入目标 `app.db` 时，会先校验目标机 Ant Browser 主程序已关闭，并自动把原 `app.db` 连同原 Cookie / 存储一起备份到 `<目标data目录>\.session-migrator-backups\<时间戳>\`。

---

## 快速使用

### 1. 编译单文件 `.exe`（在有 Go 环境的开发机上执行一次）

```bat
tools\session-migrator\build.bat
```

会在当前目录生成 `tools\session-migrator\ant-session-migrator.exe`（免 Go、免 Python、免 DLL）。

### 2. 交互式使用（推荐，直接双击或命令行运行）

- 开发机：双击 `tools\session-migrator\run-migrator.bat`（或直接运行 `ant-session-migrator.exe`）
- 导出时会依次询问登录态范围，以及是否附带导出「核心指纹」和「代理 IP 绑定」（默认均为否，按需输入 `y` 开启）。
- 目标电脑（正式版 / 另一台 dev 机）：把 `ant-session-migrator.exe` 和导出的 `.antsess` 文件拷过去，双击运行按提示导入即可；若迁移包包含指纹或代理，交互菜单会自动询问是否同步。

### 3. 命令行使用

**导出（源电脑，先停止浏览器实例）：**

```bat
:: A. 纯登录态导出（默认，不碰任何配置）
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --out sessions.antsess

:: B. 防 Google 风控推荐：登录态 + 核心指纹 + 实例绑定的最小代理 IP 节点
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --out google-full.antsess --include-fingerprint --include-proxy

:: 其他可选项：不加密自用 / 指定实例 / 仅 Cookies / 附带 IndexedDB
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --out sessions.antsess --no-password
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --profile "实例1,实例2" --cookies-only --include-fingerprint --include-proxy
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --include-indexeddb
```

**查看包摘要（无需密码，不暴露任何敏感凭据）：**

```bat
ant-session-migrator.exe inspect --in google-full.antsess
```

**导入（目标电脑正式版或 dev 版）：**

```bat
:: 1) 仅预览匹配结果（不写入任何文件）
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --dry-run

:: 2) 仅同步登录态到目标已有实例（严格不改目标 app.db）
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in sessions.antsess

:: 3) 同步登录态 + 核心指纹 + 代理 IP 到目标已有实例
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --sync-fingerprint --sync-proxy

:: 4) 目标机是全新空程序：先启动并退出一次正式版初始化 app.db，再一步建最小实例并同步登录态+指纹+代理 IP
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --create-missing --sync-fingerprint --sync-proxy

:: 5) 合并模式（保留目标实例已有其他域名 Cookie，仅覆盖冲突项）
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in sessions.antsess --cookie-mode merge
```

---

## Google 防风控操作准则（务必遵守）

1. **导出前先关闭实例**：确保 Chromium 将 `Cookies`、`Local Storage` 完全落盘，避免抓到半截或陈旧的 `__Secure-1PSIDTS` / `SIDCC`。
2. **禁止双机并发使用同一 Google 会话**：导入到 B 电脑并打开后，不要再在 A 电脑继续打开同一个 Google 账号窗口，否则双端并发轮转 `PSIDTS` / `SIDCC` 会触发 Google 会话劫持检测导致双端掉线。换回旧电脑前应重新导出一份最新 `.antsess`。
3. **保持代理出口 IP 与指纹一致**：推荐导出时加 `--include-fingerprint --include-proxy`，导入时加 `--sync-fingerprint --sync-proxy`；若未同步代理，务必在目标电脑先配好同地区/原出口代理再启动实例，切勿直连本地 IP 试探。
4. **留意未来内核升级后的 DBSC / `v20` 告警**：本工具会在导出时自动扫描 `Device Bound Sessions`（硬件 TPM 绑定）与 `v20`（App-Bound Encryption）。若未来升级到 Chromium 146+ 内核且仍希望跨机迁移 Google 登录态，建议在实例启动参数加入 `--disable-features=DeviceBoundSessions,EnableBoundSessionCredentials`。
5. **覆盖前自动备份**：默认会在 `<目标data目录>\.session-migrator-backups\<时间戳>\` 下保存覆盖前的原 Cookie、Web Storage 以及（若写入数据库）原 `app.db`，出现任何异常可直接还原。
