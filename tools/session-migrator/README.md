# Ant Browser 账号登录态离线迁移工具（零耦合独立版，Windows ↔ macOS 跨系统）

本工具位于 `tools/session-migrator/`，自带独立的 `go.mod`，**与主项目代码无任何导入或构建耦合**。编译后的二进制为纯 Go 单文件免依赖程序，同时支持 **Windows ↔ Windows**、**Windows ↔ macOS**、**macOS ↔ macOS** 跨系统迁移，兼容开发版与正式版。

## 核心原理（为什么干净且不触发 Google 风控）

1. **全程离线重加密，零启动浏览器、零网络发包**
   - **Windows 端**：离线通过本机 Windows DPAPI 加解密 `Local State` 的 32 字节密钥 + `v10` AES-256-GCM + schema v24 `SHA256(host_key)`。
   - **macOS 端**：离线通过本机 macOS 钥匙串（自动识别 `Chromium Safe Storage` / `Chrome Safe Storage`）派生 16 字节密钥（`PBKDF2-HMAC-SHA1`，salt=`saltysalt`，`1003` 次迭代）+ `v10` AES-128-CBC（16 空格 IV + PKCS#7）+ schema v24 `SHA256(host_key)`。
   - 迁移包 `.antsess` 内部保存逻辑 Cookie（完整保留 20 列原始字段与时间戳）及 Web Storage，与源操作系统加密方式彻底解耦，因此 **Windows 导出的 `.antsess` 可以直接导入 macOS**，反之亦然。
2. **默认只迁登录态，可选最干净的「代理 IP」与「核心指纹」同步**
   - **默认必迁（登录态）**：`Default/Network/Cookies` + `Default/Local Storage/leveldb` + `Default/Session Storage`（可选 `--cookies-only` 或 `--include-indexeddb`）。
   - **可选迁移核心指纹（`--include-fingerprint` / `--sync-fingerprint`）**：仅迁移 `fingerprint_args`（若源实例未显式写 `--fingerprint=`，自动物化出确定性种子）；Ant Browser 在 macOS 上运行 Windows 指纹时会自动关闭字体伪装防缺字，同时保持 Google 看到的浏览器指纹连续性。
   - **可选迁移代理 IP（`--include-proxy` / `--sync-proxy`）**：仅迁移被选中实例**实际引用**的最小代理节点（`proxy_config`、`preferred_kernel`、`dns_servers`、`group_name`，兼容 xray / sing-box / 虚拟分组），绝不导出订阅 URL、历史测速或未引用节点；导入时按 `proxy_config` 自动去重复用，不覆盖无关节点。
   - **绝不触碰**：`config.yaml`、插件、书签、分组、标签、历史记录、缓存、`Preferences`、`Secure Preferences`。
3. **默认不改目标 `app.db`，按需安全写入并自动备份**
   - 自动识别 Windows 开发版/正式版以及 macOS 正式版独立状态目录（`~/Library/Application Support/ant-browser`，即使传入 `Ant Browser.app` 路径也会自动重定向）。
   - 涉及写入 `app.db`（`--create-missing` / `--sync-fingerprint` / `--sync-proxy`）前会校验主程序已退出并自动备份原 `app.db` 与 Cookie/存储到 `.session-migrator-backups/<时间戳>/`。

---

## 快速编译与启动脚本

- **macOS 本地源码启动（自动编译）**：直接运行 `tools/session-migrator/run-migrator.sh`（首次缺失二进制时自动以纯 Go `CGO_ENABLED=0` 编译本机 `arm64`/`amd64` 单文件 `ant-session-migrator`，之后直接复用；源码改动后可执行 `MIGRATOR_REBUILD=1 ./tools/session-migrator/run-migrator.sh` 强制重编；无参数进入中文交互菜单，带参数原样透传给 CLI）
- **Windows 本地编译与启动**：运行 `tools\session-migrator\build.bat` 生成 `ant-session-migrator.exe`，或直接运行 `tools\session-migrator\run-migrator.bat`（缺失时自动编译）
- **Windows 一键交叉编译 macOS（arm64 Apple Silicon + amd64 Intel）与 Windows**：
  ```bat
  tools\session-migrator\build-mac.bat
  ```
  会在 `publish\output\` 生成带 Unix 可执行权限（`0755`）与双击脚本 `run-migrator.command` 的压缩包：
  - `publish\output\ant-session-migrator-1.2.0-macos-arm64.zip`（M1/M2/M3/M4）
  - `publish\output\ant-session-migrator-1.2.0-macos-amd64.zip`（Intel Mac）

---

## macOS 使用步骤（支持开发版 `./scripts/dev-mac.sh` 与正式版）

### 方式 A：macOS 开发版（项目根目录数据，搭配 `./scripts/dev-mac.sh`）

1. 先用 `./scripts/dev-mac.sh` 启动一次 Ant Browser，完成 `<项目根>/data/app.db` 初始化与 `<项目根>/chrome/` 内核配置，然后**彻底退出 Ant Browser**（`Cmd + Q` 或 `Ctrl + C`）。
2. 在项目根目录直接通过 `run-migrator.sh` 执行（脚本会自动编译本机单文件并保留调用方当前目录，相对路径可直接使用）：
   ```bash
   # 进入中文交互菜单（无参数）
   ./tools/session-migrator/run-migrator.sh

   # 查看迁移包摘要（无需密码）
   ./tools/session-migrator/run-migrator.sh inspect \
     --in "/Users/<用户名>/Downloads/ant-sessions-full.antsess"

   # 预览导入计划（Dry-Run，不写入任何文件）
   ./tools/session-migrator/run-migrator.sh import \
     --app-root . \
     --in "/Users/<用户名>/Downloads/ant-sessions-full.antsess" \
     --create-missing --sync-fingerprint --sync-proxy --dry-run

   # 正式离线导入到当前项目根目录（写入 data/app.db 与 data/<profile_id>/Default/）
   ./tools/session-migrator/run-migrator.sh import \
     --app-root . \
     --in "/Users/<用户名>/Downloads/ant-sessions-full.antsess" \
     --create-missing --sync-fingerprint --sync-proxy

   # 从 macOS 开发版离线导出（同样支持跨系统导回 Windows）
   ./tools/session-migrator/run-migrator.sh export \
     --app-root . \
     --out "./mac-sessions-full.antsess" \
     --include-fingerprint --include-proxy --skip-unreadable
   ```
3. 导入完成后重新执行 `./scripts/dev-mac.sh` 启动应用即可看到已迁移实例；原数据库会自动回滚备份到 `data/.session-migrator-backups/<时间戳>/`。
4. 若此前从未在 Mac 上启动过 Chromium，工具会自动在登录钥匙串创建兼容的 `Chromium Safe Storage`；首次从 Ant Browser 打开导入后的实例时若 macOS 提示钥匙串授权，点击 **始终允许** 即可。

### 方式 B：macOS 正式版（独立状态目录 `~/Library/Application Support/ant-browser`）

1. **安装并初始化 macOS 正式版**：
   - 将 `AntBrowser-<版本>-macos-<arm64|amd64>.zip` 解压得到 `.app`，去掉隔离属性后首次打开：
     ```bash
     xattr -dr com.apple.quarantine "AntBrowser-1.9.3-macos-arm64.app"
     open "AntBrowser-1.9.3-macos-arm64.app"
     ```
   - 在 Ant Browser 中下载/配置好 macOS 版 Chromium 内核后，**建议新建并打开关闭一次空白测试实例**（让 Chromium 自己写入本机钥匙串 `Chromium Safe Storage`，后续不会反复弹钥匙串授权），然后**彻底退出 Ant Browser**（`Cmd + Q`）。
2. **解压并运行预编译版（或源码版 `run-migrator.sh`）**：
   - 解压 `ant-session-migrator-1.2.0-macos-arm64.zip`（Intel Mac 用 `amd64`），终端执行（或双击 `run-migrator.command` 进入交互菜单）：
     ```bash
     xattr -dr com.apple.quarantine ./ant-session-migrator
     chmod +x ./ant-session-migrator

     # 一步导入到 macOS 正式版状态目录（自动识别 ~/Library/Application Support/ant-browser）
     ./ant-session-migrator import \
       --app-root "~/Library/Application Support/ant-browser" \
       --in "/path/to/ant-sessions-full.antsess" \
       --create-missing --sync-fingerprint --sync-proxy
     ```
   - 运行时若 macOS 弹出「security 想要访问钥匙串 Chromium Safe Storage」，点击 **允许 / 始终允许** 即可（整批导入只会读取一次并缓存）。
   - 如果此前从未在 Mac 上启动过 Chromium，本工具会自动在钥匙串创建兼容的 `Chromium Safe Storage`；首次打开导入后的实例时若 macOS 提示 Chromium 访问钥匙串，点 **始终允许** 即可。
   - 若你在 macOS 上使用的是官方 `Google Chrome.app` 而非 `Chromium.app`，工具会自动识别 `Chrome Safe Storage`，也可显式传 `--keychain-service "Chrome Safe Storage"`。

---

## Windows 命令行示例

**导出（先停止实例）：**
```bat
:: 防 Google 风控完整导出（登录态 + 核心指纹 + 最小代理 IP 节点）
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --out google-full.antsess --include-fingerprint --include-proxy --skip-unreadable

:: 仅登录态导出 / 不加密自用
ant-session-migrator.exe export --app-root D:\Code\IdeaProjects\Ant-Browser --out sessions.antsess --no-password
```

**查看迁移包摘要（无需密码）：**
```bat
ant-session-migrator.exe inspect --in google-full.antsess
```

**导入（开发版或正式版）：**
```bat
:: 预览匹配结果
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --dry-run

:: 同步到已有匹配实例
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --sync-fingerprint --sync-proxy

:: 全新空程序（先启停一次初始化 app.db）一步导入
ant-session-migrator.exe import --app-root "%LOCALAPPDATA%\Programs\Ant Browser" --in google-full.antsess --create-missing --sync-fingerprint --sync-proxy
```

---

## Google 防风控操作准则

1. **导出前先关闭实例**：确保 `Cookies` 与 `Local Storage` 完整落盘。
2. **禁止双机并发使用同一 Google 会话**：在 Mac 上打开导入的 Google 账号后，不要再在原 Windows 电脑打开同一个账号，避免 `__Secure-1PSIDTS` / `SIDCC` 双端轮转冲突触发验证。
3. **保持代理出口 IP 与指纹一致**：建议开启 `--include-fingerprint --include-proxy` / `--sync-fingerprint --sync-proxy`，切勿用本地直连 IP 试探。
4. **留意未来内核升级的 DBSC / `v20` 告警**：工具会自动检测并提示；如未来升级至 Chromium 146+ 仍需跨机迁移，可在启动参数加入 `--disable-features=DeviceBoundSessions,EnableBoundSessionCredentials`。
