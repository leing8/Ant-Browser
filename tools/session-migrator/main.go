// main.go 为零耦合独立迁移工具的 CLI 与中文交互式菜单入口。
// 无参运行（如直接双击 .exe / .command）自动进入交互引导模式；传参运行支持 export / import / inspect 子命令。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// multiStringFlag 支持同一 CLI 参数重复传入或逗号分隔（如 --profile "a,b" --profile "c"）。
type multiStringFlag []string

// String 实现 flag.Value 接口，将多值参数拼接为逗号分隔字符串。
func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

// Set 实现 flag.Value 接口，支持逗号拆分子项并追加到参数切片。
func (m *multiStringFlag) Set(val string) error {
	for _, part := range strings.Split(val, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			*m = append(*m, trimmed)
		}
	}
	return nil
}

// main 根据命令行参数分发子命令，无参数时默认进入交互式向导菜单。
func main() {
	if len(os.Args) < 2 {
		runInteractive()
		return
	}

	cmd := strings.ToLower(strings.TrimSpace(os.Args[1]))
	switch cmd {
	case "export":
		if err := handleExportCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "\n[错误] %v\n", err)
			os.Exit(1)
		}
	case "import":
		if err := handleImportCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "\n[错误] %v\n", err)
			os.Exit(1)
		}
	case "inspect":
		if err := handleInspectCLI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "\n[错误] %v\n", err)
			os.Exit(1)
		}
	case "interactive", "menu":
		runInteractive()
	case "version", "-v", "--version":
		fmt.Printf("ant-session-migrator v%s\n", toolVersion)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// printUsage 输出 CLI 子命令说明与常用示例。
func printUsage() {
	fmt.Printf(`Ant Browser 账号登录态离线迁移工具 v%s（零耦合独立版）

核心特点：
  - 全程离线加解密（Windows: DPAPI+AES-256-GCM；macOS: Keychain Safe Storage+AES-128-CBC），支持 Windows <-> macOS 跨系统迁移，不启动浏览器、零网络请求
  - 默认仅迁移账号登录态（Cookies + Local Storage + Session Storage），绝不触碰其他无关配置
  - 可按需开启「核心指纹」与「代理 IP 绑定」干净迁移（防 Google 风控一步到位，不含订阅/测速/插件/书签）
  - 同时兼容开发版、Windows 正式版与 macOS 正式版（自动定位 ~/Library/Application Support/ant-browser）

用法：
  ant-session-migrator                       进入交互式菜单（适合直接双击或配合 .bat 使用）
  ant-session-migrator export  [选项]         导出账号登录态为 .antsess 迁移包
  ant-session-migrator import  [选项]         导入 .antsess 迁移包到目标电脑的 Ant Browser
  ant-session-migrator inspect -in <文件>     查看迁移包摘要（无需密码）

导出选项（export）：
  --app-root <目录>          源 Ant Browser 目录（dev 仓库根目录或正式版安装目录）
  --out <文件>               输出文件路径（默认当前目录 ant-sessions-YYYYMMDD-HHMMSS.antsess）
  --password <密码>          加密密码（不传且未加 --no-password 时会交互提示）
  --password-env <变量名>    从环境变量读取加密密码
  --no-password              不加密（明文 ZIP 载荷，仅建议本机/局域网自用且用完即删）
  --profile <ID或名称>       仅导出指定实例（可重复或逗号分隔）
  --cookies-only             仅导出 Cookies，不包含 Local Storage / Session Storage
  --include-indexeddb        额外包含 IndexedDB（体积较大，默认关闭）
  --include-fingerprint      [可选] 附带导出实例核心指纹 fingerprint_args（默认关闭，存放在加密载荷内）
  --include-proxy            [可选] 附带导出实例绑定的最小代理 IP 节点（默认关闭，不含订阅/测速历史，存放在加密载荷内）
  --include-deleted          包含回收站中的已删除实例（默认关闭）
  --skip-locked              遇到运行中的实例自动跳过（默认报错提醒先关闭）
  --skip-unreadable          遇到本机密钥无法解密的异常/跨机遗留实例自动跳过并告警（默认报错中止）
  --keychain-service <名称>  [仅 macOS] 指定钥匙串项名（默认自动识别 Chromium Safe Storage / Chrome Safe Storage）
  --keychain-password <密码> [仅 macOS] 手动指定 Safe Storage 密钥（也可用环境变量 ANT_KEYCHAIN_PASSWORD）

导入选项（import）：
  --app-root <目录>          目标 Ant Browser 目录（dev 仓库、Windows 正式版或 macOS .app / Application Support 目录）
  --in <文件>                待导入的 .antsess 迁移包路径
  --password <密码>          解密密码（仅加密包需要）
  --password-env <变量名>    从环境变量读取解密密码
  --profile <ID或名称>       仅导入指定实例（可重复或逗号分隔）
  --match-by <策略>          实例匹配方式：id-or-name（默认）| id | name
  --create-missing           目标无对应实例时，在目标 app.db 自动创建最小空壳实例（默认关闭，不改 app.db）
  --sync-fingerprint         [可选] 同步迁移包中的核心指纹到目标实例（适用于已有匹配实例与新建实例，默认关闭）
  --sync-proxy               [可选] 同步迁移包中的代理 IP 绑定到目标实例（自动去重复用节点，不覆盖无关代理，默认关闭）
  --cookie-mode <模式>       Cookies 写入模式：replace（默认，最干净）| merge（合并保留旧域名）
  --dry-run                  仅预览匹配结果，不写入任何文件
  --no-backup                覆盖前不生成本地回滚备份（默认会自动备份 Cookie/存储与 app.db）
  --force                    跳过 Ant Browser 主程序运行检查（不推荐）
  --keychain-service <名称>  [仅 macOS] 指定钥匙串项名（默认自动识别 Chromium Safe Storage / Chrome Safe Storage）
  --keychain-password <密码> [仅 macOS] 手动指定 Safe Storage 密钥（也可用环境变量 ANT_KEYCHAIN_PASSWORD）
`, toolVersion)
}

// handleExportCLI 解析 export 子命令参数并执行离线导出。
func handleExportCLI(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var opts ExportOptions
	var passwordEnv string
	var cookiesOnly bool
	var profiles multiStringFlag

	fs.StringVar(&opts.AppRoot, "app-root", "", "Ant Browser 根目录")
	fs.StringVar(&opts.OutputPath, "out", "", "输出迁移包路径")
	fs.StringVar(&opts.Password, "password", "", "迁移包加密密码")
	fs.StringVar(&passwordEnv, "password-env", "", "读取加密密码的环境变量名")
	fs.BoolVar(&opts.NoPassword, "no-password", false, "不设密码（明文打包）")
	fs.Var(&profiles, "profile", "仅导出指定实例 ID 或名称（可多次传入或逗号分隔）")
	fs.BoolVar(&cookiesOnly, "cookies-only", false, "仅导出 Cookies")
	fs.BoolVar(&opts.IncludeIndexedDB, "include-indexeddb", false, "额外导出 IndexedDB")
	fs.BoolVar(&opts.IncludeFingerprint, "include-fingerprint", false, "附带导出核心指纹 fingerprint_args")
	fs.BoolVar(&opts.IncludeProxy, "include-proxy", false, "附带导出实例绑定的最小代理 IP 节点")
	fs.BoolVar(&opts.IncludeDeleted, "include-deleted", false, "包含回收站实例")
	fs.BoolVar(&opts.SkipLocked, "skip-locked", false, "跳过运行中的实例")
	fs.BoolVar(&opts.SkipUnreadable, "skip-unreadable", false, "跳过本机密钥无法解密的实例")
	fs.StringVar(&opts.KeychainService, "keychain-service", "", "[仅 macOS] Safe Storage 钥匙串服务名")
	fs.StringVar(&opts.KeychainPassword, "keychain-password", "", "[仅 macOS] Safe Storage 密钥明文")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.KeychainPassword == "" {
		opts.KeychainPassword = os.Getenv("ANT_KEYCHAIN_PASSWORD")
	}

	opts.ProfileFilters = profiles
	opts.IncludeLocalStorage = !cookiesOnly
	opts.IncludeSessionStorage = !cookiesOnly

	if opts.AppRoot == "" {
		detected := discoverAppInstallations()
		if len(detected) == 1 {
			opts.AppRoot = detected[0].AppRoot
			fmt.Printf("自动识别到 Ant Browser 目录: %s [%s]\n", opts.AppRoot, detected[0].Mode)
		} else {
			return fmt.Errorf("请通过 --app-root 指定 Ant Browser 根目录（或直接无参运行进入交互菜单）")
		}
	}

	if !opts.NoPassword && opts.Password == "" && passwordEnv != "" {
		opts.Password = os.Getenv(passwordEnv)
	}
	if !opts.NoPassword && opts.Password == "" {
		reader := bufio.NewReader(os.Stdin)
		pass, noPass, err := promptExportPassword(reader, opts.IncludeProxy)
		if err != nil {
			return err
		}
		opts.Password = pass
		opts.NoPassword = noPass
	}

	summary, err := runExport(opts)
	if err != nil {
		return err
	}
	printExportSummary(summary)
	return nil
}

// handleImportCLI 解析 import 子命令参数并执行离线导入或 Dry-Run 预览。
func handleImportCLI(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	var opts ImportOptions
	var passwordEnv string
	var profiles multiStringFlag

	fs.StringVar(&opts.AppRoot, "app-root", "", "目标 Ant Browser 根目录")
	fs.StringVar(&opts.InputPath, "in", "", "待导入的 .antsess 迁移包路径")
	fs.StringVar(&opts.Password, "password", "", "迁移包解密密码")
	fs.StringVar(&passwordEnv, "password-env", "", "读取解密密码的环境变量名")
	fs.Var(&profiles, "profile", "仅导入指定实例 ID 或名称")
	fs.StringVar(&opts.MatchBy, "match-by", "id-or-name", "匹配策略: id-or-name | id | name")
	fs.BoolVar(&opts.CreateMissing, "create-missing", false, "目标无对应实例时自动创建最小空壳实例")
	fs.BoolVar(&opts.SyncFingerprint, "sync-fingerprint", false, "同步源实例核心指纹 fingerprint_args")
	fs.BoolVar(&opts.SyncProxy, "sync-proxy", false, "同步源实例代理 IP 绑定与最小节点")
	fs.StringVar(&opts.CookieMode, "cookie-mode", "replace", "Cookie 写入模式: replace | merge")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "仅预览匹配计划不修改磁盘")
	fs.BoolVar(&opts.NoBackup, "no-backup", false, "跳过自动备份")
	fs.BoolVar(&opts.Force, "force", false, "跳过主程序运行检查")
	fs.StringVar(&opts.KeychainService, "keychain-service", "", "[仅 macOS] Safe Storage 钥匙串服务名")
	fs.StringVar(&opts.KeychainPassword, "keychain-password", "", "[仅 macOS] Safe Storage 密钥明文")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.KeychainPassword == "" {
		opts.KeychainPassword = os.Getenv("ANT_KEYCHAIN_PASSWORD")
	}
	opts.ProfileFilters = profiles

	if strings.TrimSpace(opts.InputPath) == "" {
		return fmt.Errorf("请通过 --in 指定迁移包文件路径")
	}
	if opts.AppRoot == "" {
		detected := discoverAppInstallations()
		if len(detected) == 1 {
			opts.AppRoot = detected[0].AppRoot
			fmt.Printf("自动识别到目标 Ant Browser 目录: %s [%s]\n", opts.AppRoot, detected[0].Mode)
		} else {
			return fmt.Errorf("请通过 --app-root 指定目标 Ant Browser 根目录（或直接无参运行进入交互菜单）")
		}
	}

	manifest, err := readArchiveManifest(opts.InputPath)
	if err != nil {
		return err
	}
	if manifest.Encrypted {
		if opts.Password == "" && passwordEnv != "" {
			opts.Password = os.Getenv(passwordEnv)
		}
		if opts.Password == "" {
			reader := bufio.NewReader(os.Stdin)
			pass, pErr := promptPasswordOnce(reader, "请输入迁移包解密密码: ")
			if pErr != nil {
				return pErr
			}
			opts.Password = pass
		}
	}

	summary, err := runImport(opts)
	if err != nil {
		return err
	}
	printImportSummary(summary)
	return nil
}

// handleInspectCLI 读取并打印迁移包公开摘要 manifest.json（无需解密密码）。
func handleInspectCLI(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	var inputPath string
	fs.StringVar(&inputPath, "in", "", "迁移包文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(inputPath) == "" && fs.NArg() > 0 {
		inputPath = fs.Arg(0)
	}
	if strings.TrimSpace(inputPath) == "" {
		return fmt.Errorf("请通过 --in 指定迁移包文件路径")
	}
	manifest, err := readArchiveManifest(inputPath)
	if err != nil {
		return err
	}
	printManifestSummary(inputPath, manifest)
	return nil
}

// runInteractive 启动面向非命令行用户的中文交互式向导菜单。
func runInteractive() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("============================================================")
	fmt.Printf("  Ant Browser 账号登录态离线迁移工具 v%s\n", toolVersion)
	fmt.Printf("  当前加密后端: %s | 零启动浏览器 | 可选代理 IP 与指纹\n", platformCryptoLabel())
	fmt.Println("============================================================")
	fmt.Println()

	for {
		fmt.Println("请选择操作：")
		fmt.Println("  [1] 导出登录态（可选附带核心指纹与代理 IP）")
		fmt.Println("  [2] 导入登录态（导入到本机正式版或 dev 版）")
		fmt.Println("  [3] 查看迁移包信息（无需密码）")
		fmt.Println("  [0] 退出")
		fmt.Print("\n请输入序号 [1/2/3/0]: ")

		choice := readLineTrim(reader)
		fmt.Println()
		switch choice {
		case "1":
			if err := interactiveExport(reader); err != nil {
				fmt.Printf("[错误] %v\n\n", err)
			}
		case "2":
			if err := interactiveImport(reader); err != nil {
				fmt.Printf("[错误] %v\n\n", err)
			}
		case "3":
			if err := interactiveInspect(reader); err != nil {
				fmt.Printf("[错误] %v\n\n", err)
			}
		case "0", "q", "quit", "exit":
			return
		default:
			fmt.Println("无效选择，请重新输入。")
			fmt.Println()
		}
	}
}

// interactiveExport 交互式引导用户选择源目录、存储范围、可选指纹/代理与输出密码并执行导出。
func interactiveExport(reader *bufio.Reader) error {
	appRoot, err := promptSelectAppRoot(reader, "选择要导出登录态的源 Ant Browser 目录")
	if err != nil {
		return err
	}

	fmt.Println("\n选择登录态存储范围：")
	fmt.Println("  [1] 标准推荐：Cookies + Local Storage + Session Storage（最干净，覆盖 Google 及绝大多数站点）")
	fmt.Println("  [2] 极致精简：仅 Cookies（适合纯 Google 账号）")
	fmt.Println("  [3] 完整 Web 存储：Cookies + Local Storage + Session Storage + IndexedDB（体积较大）")
	fmt.Print("请选择 [默认 1]: ")
	scopeChoice := readLineTrim(reader)
	includeLS, includeSS, includeIDB := true, true, false
	switch scopeChoice {
	case "2":
		includeLS, includeSS, includeIDB = false, false, false
	case "3":
		includeLS, includeSS, includeIDB = true, true, true
	}

	fmt.Println("\n防 Google 风控可选项（默认均为否，保持纯登录态；按需开启）：")
	fmt.Print("  是否附带导出「核心指纹」fingerprint_args（保持目标机指纹种子/语言/时区一致）？[y/N]: ")
	includeFP := isYes(readLineTrim(reader))
	fmt.Print("  是否附带导出「代理 IP 绑定」（仅导出被引用最小节点，不含订阅与测速记录）？[y/N]: ")
	includeProxy := isYes(readLineTrim(reader))

	defaultOut := defaultExportFileName(time.Now())
	fmt.Printf("\n输出文件路径 [直接回车使用当前目录 %s]: ", defaultOut)
	outPath := stripSurroundingQuotes(readLineTrim(reader))
	if outPath == "" {
		outPath = defaultOut
	}

	pass, noPass, err := promptExportPassword(reader, includeProxy)
	if err != nil {
		return err
	}

	fmt.Println()
	summary, err := runExport(ExportOptions{
		AppRoot:               appRoot,
		OutputPath:            outPath,
		Password:              pass,
		NoPassword:            noPass,
		IncludeLocalStorage:   includeLS,
		IncludeSessionStorage: includeSS,
		IncludeIndexedDB:      includeIDB,
		IncludeFingerprint:    includeFP,
		IncludeProxy:          includeProxy,
		SkipUnreadable:        true,
	})
	if err != nil {
		return err
	}
	printExportSummary(summary)
	return nil
}

// interactiveImport 交互式引导用户预览迁移包、匹配目标实例、确认同步选项并执行导入。
func interactiveImport(reader *bufio.Reader) error {
	fmt.Print("请输入或拖入 .antsess 迁移包路径: ")
	inPath := stripSurroundingQuotes(readLineTrim(reader))
	if inPath == "" {
		return fmt.Errorf("未输入迁移包路径")
	}

	manifest, err := readArchiveManifest(inPath)
	if err != nil {
		return err
	}
	fmt.Println()
	printManifestSummary(inPath, manifest)

	appRoot, err := promptSelectAppRoot(reader, "选择要导入登录态的目标 Ant Browser 目录（正式版或 dev 版）")
	if err != nil {
		return err
	}

	inst, err := resolveAppInstallation(appRoot)
	if err != nil {
		return err
	}

	// 先做一次零写入预览
	previewItems, _, err := planImport(inst, manifest, ImportOptions{
		AppRoot:       appRoot,
		InputPath:     inPath,
		MatchBy:       "id-or-name",
		CreateMissing: false,
	})
	if err != nil {
		return err
	}

	matchedCnt, unmatchedCnt, ambiguousCnt := 0, 0, 0
	for _, item := range previewItems {
		switch item.Action {
		case "match-id", "match-name":
			matchedCnt++
		case "skip-unmatched":
			unmatchedCnt++
		case "skip-ambiguous":
			ambiguousCnt++
		}
	}

	fmt.Printf("\n匹配预览：目标已有匹配实例 %d 个，未匹配 %d 个", matchedCnt, unmatchedCnt)
	if ambiguousCnt > 0 {
		fmt.Printf("，同名冲突跳过 %d 个", ambiguousCnt)
	}
	fmt.Println()

	createMissing := false
	if unmatchedCnt > 0 {
		fmt.Printf("目标程序中缺少 %d 个对应实例。\n", unmatchedCnt)
		fmt.Print("是否为这批未匹配实例在目标 app.db 自动创建最小空壳实例（其余配置不动）？[y/N]: ")
		createMissing = isYes(readLineTrim(reader))
	}

	if matchedCnt == 0 && !createMissing {
		fmt.Println("没有任何可写入的目标实例，已取消导入。")
		return nil
	}

	syncFP := false
	if manifestHasFingerprintData(manifest) {
		fmt.Print("\n迁移包包含「核心指纹」数据，是否同步写入目标实例（降低 Google 指纹跳变风控）？[Y/n]: ")
		syncFP = isYesDefaultTrue(readLineTrim(reader))
	}

	syncProxy := false
	if manifestHasProxyData(manifest) {
		fmt.Print("迁移包包含「代理 IP 绑定」数据，是否同步写入目标实例（自动去重复用，不覆盖无关节点）？[Y/n]: ")
		syncProxy = isYesDefaultTrue(readLineTrim(reader))
	}

	fmt.Print("\nCookie 写入模式：[1] 覆盖目标实例原 Cookie（默认推荐，最干净） / [2] 合并保留旧域名 [默认 1]: ")
	modeAns := readLineTrim(reader)
	cookieMode := "replace"
	if modeAns == "2" {
		cookieMode = "merge"
	}

	pass := ""
	if manifest.Encrypted {
		pass, err = promptPasswordOnce(reader, "\n请输入迁移包解密密码: ")
		if err != nil {
			return err
		}
	}

	fmt.Println()
	summary, err := runImport(ImportOptions{
		AppRoot:         appRoot,
		InputPath:       inPath,
		Password:        pass,
		MatchBy:         "id-or-name",
		CreateMissing:   createMissing,
		SyncFingerprint: syncFP,
		SyncProxy:       syncProxy,
		CookieMode:      cookieMode,
	})
	if err != nil {
		return err
	}
	printImportSummary(summary)
	return nil
}

// interactiveInspect 交互式读取并打印指定 .antsess 迁移包的公开摘要清单。
func interactiveInspect(reader *bufio.Reader) error {
	fmt.Print("请输入或拖入 .antsess 迁移包路径: ")
	inPath := stripSurroundingQuotes(readLineTrim(reader))
	if inPath == "" {
		return fmt.Errorf("未输入迁移包路径")
	}
	manifest, err := readArchiveManifest(inPath)
	if err != nil {
		return err
	}
	printManifestSummary(inPath, manifest)
	return nil
}

// promptSelectAppRoot 自动列出本机探测到的开发版与正式版目录供用户编号选择，也支持直接粘贴自定义路径。
func promptSelectAppRoot(reader *bufio.Reader, title string) (string, error) {
	detected := discoverAppInstallations()
	fmt.Printf("%s：\n", title)
	for i, d := range detected {
		modeTag := "正式版"
		if d.Mode == "dev" {
			modeTag = "开发版 dev.bat"
		}
		dbTag := fmt.Sprintf("活跃实例 %d 个", d.ActiveCount)
		if !d.HasAppDB {
			dbTag = "未发现 data/app.db（请先启动并关闭一次程序）"
		}
		fmt.Printf("  [%d] [%s] %s  (%s | %s)\n", i+1, modeTag, d.AppRoot, d.DetectedLabel, dbTag)
	}
	fmt.Printf("  [%d] 手动输入目录路径\n", len(detected)+1)

	if len(detected) > 0 {
		fmt.Printf("请选择 [默认 1]: ")
	} else {
		fmt.Print("请输入 Ant Browser 根目录路径: ")
	}
	input := stripSurroundingQuotes(readLineTrim(reader))
	if len(detected) == 0 {
		if input == "" {
			return "", fmt.Errorf("未输入目录路径")
		}
		return input, nil
	}
	if input == "" {
		return detected[0].AppRoot, nil
	}
	if n, err := strconv.Atoi(input); err == nil {
		if n >= 1 && n <= len(detected) {
			return detected[n-1].AppRoot, nil
		}
		if n == len(detected)+1 {
			fmt.Print("请输入 Ant Browser 根目录路径: ")
			custom := stripSurroundingQuotes(readLineTrim(reader))
			if custom == "" {
				return "", fmt.Errorf("未输入目录路径")
			}
			return custom, nil
		}
	}
	return input, nil
}

// promptExportPassword 引导用户输入两次加密密码（关闭回显），直接回车时二次确认是否明文导出。
func promptExportPassword(reader *bufio.Reader, includeProxy bool) (password string, noPassword bool, err error) {
	hint := "\n设置迁移包密码（建议设置；直接回车可选择不加密）: "
	if includeProxy {
		hint = "\n设置迁移包密码（包含代理账号/Cookie 强烈建议设密码；直接回车可选择不加密）: "
	}
	p1, err := promptPasswordOnce(reader, hint)
	if err != nil {
		return "", false, err
	}
	if p1 == "" {
		fmt.Print("[提示] 未设置密码，导出包内登录态/代理信息将以未加密 ZIP 存放（用完请及时删除）。确认不加密继续？[y/N]: ")
		if isYes(readLineTrim(reader)) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("已取消导出")
	}
	if len([]rune(p1)) < minPasswordRunes {
		return "", false, fmt.Errorf("密码至少需要 %d 个字符", minPasswordRunes)
	}
	p2, err := promptPasswordOnce(reader, "请再次输入密码确认: ")
	if err != nil {
		return "", false, err
	}
	if p1 != p2 {
		return "", false, fmt.Errorf("两次输入的密码不一致")
	}
	return p1, false, nil
}

// promptPasswordOnce 临时关闭终端回显并读取单行密码输入。
func promptPasswordOnce(reader *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)
	restore := setConsoleEcho(false)
	line, err := reader.ReadString('\n')
	restore()
	fmt.Println()
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readLineTrim 从缓冲流读取一行并去除首尾空白字符。
func readLineTrim(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// isYes 判断用户输入是否为显式肯定（y/yes，默认为否）。
func isYes(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	return low == "y" || low == "yes"
}

// isYesDefaultTrue 判断用户输入是否为肯定（空回车默认视为是）。
func isYesDefaultTrue(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return true
	}
	return low == "y" || low == "yes"
}

// stripSurroundingQuotes 去除用户拖拽文件到终端窗口时系统自动包裹的首尾引号。
func stripSurroundingQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// printManifestSummary 格式化输出 .antsess 迁移包的清单摘要、实例统计与导出告警。
func printManifestSummary(path string, m *ArchiveManifest) {
	encStatus := "已加密（scrypt + AES-256-GCM）"
	if !m.Encrypted {
		encStatus = "未加密（明文 ZIP，传输后请及时删除）"
	}
	var scopes []string
	scopes = append(scopes, "Cookies")
	if m.IncludeLocalStorage {
		scopes = append(scopes, "Local Storage")
	}
	if m.IncludeSessionStorage {
		scopes = append(scopes, "Session Storage")
	}
	if m.IncludeIndexedDB {
		scopes = append(scopes, "IndexedDB")
	}
	if manifestHasFingerprintData(m) {
		scopes = append(scopes, "核心指纹")
	}
	if manifestHasProxyData(m) {
		scopes = append(scopes, "代理 IP")
	}

	fmt.Println("------------------------------------------------------------")
	fmt.Printf("迁移包文件: %s\n", path)
	fmt.Printf("导出时间:   %s\n", m.ExportedAt)
	fmt.Printf("加密状态:   %s\n", encStatus)
	fmt.Printf("包含内容:   %s\n", strings.Join(scopes, " + "))
	fmt.Printf("实例数量:   %d\n", m.ProfileCount)
	fmt.Println("------------------------------------------------------------")
	for i, p := range m.Profiles {
		flags := []string{fmt.Sprintf("Cookies=%d", p.CookieCount)}
		if p.GoogleCookieCount > 0 {
			flags = append(flags, fmt.Sprintf("Google=%d", p.GoogleCookieCount))
		}
		if p.HasLocalStorage {
			flags = append(flags, "LS")
		}
		if p.HasSessionStorage {
			flags = append(flags, "SS")
		}
		if p.HasIndexedDB {
			flags = append(flags, "IDB")
		}
		if p.HasFingerprint || len(p.LegacyFingerprintArgs) > 0 {
			flags = append(flags, "FP")
		}
		if p.HasProxy {
			if p.ProxySummary != "" {
				flags = append(flags, "Proxy:"+p.ProxySummary)
			} else {
				flags = append(flags, "Proxy")
			}
		}
		if p.V20CookieCount > 0 {
			flags = append(flags, fmt.Sprintf("⚠v20=%d", p.V20CookieCount))
		}
		if p.DBSCSessionCount > 0 {
			flags = append(flags, fmt.Sprintf("⚠DBSC=%d", p.DBSCSessionCount))
		}
		fmt.Printf("  %2d. %-24s (%s)  [%s]\n", i+1, p.ProfileName, shortID(p.ProfileID), strings.Join(flags, ", "))
	}
	if len(m.Warnings) > 0 {
		fmt.Println("\n[导出阶段告警]")
		for _, w := range m.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
	fmt.Println()
}

// printExportSummary 打印导出结果汇总、跳过统计与 Google 动态令牌防风控提醒。
func printExportSummary(s *ExportSummary) {
	fmt.Println("\n============================================================")
	fmt.Println("  导出完成（全程离线，未启动浏览器，零网络发包）")
	fmt.Println("============================================================")
	fmt.Printf("输出文件:     %s (%.2f MB)\n", s.OutputPath, float64(s.ArchiveSizeBytes)/1024/1024)
	if s.Encrypted {
		fmt.Println("保护方式:     密码加密（scrypt + AES-256-GCM）")
	} else {
		fmt.Println("保护方式:     [注意] 未加密！迁移完成后请立即删除此文件")
	}
	fmt.Printf("导出实例数:   %d（总 Cookie: %d，其中 Google 相关: %d）\n", s.ExportedProfiles, s.TotalCookies, s.TotalGoogleCookies)
	if s.ExportedFingerprints > 0 || s.ExportedProxies > 0 {
		fmt.Printf("可选增强项:   核心指纹 %d 个 | 代理 IP 绑定 %d 个（均保存在内层载荷中）\n", s.ExportedFingerprints, s.ExportedProxies)
	}
	if s.SkippedLockedProfiles > 0 {
		fmt.Printf("跳过运行中:   %d 个实例\n", s.SkippedLockedProfiles)
	}
	if s.SkippedUnreadable > 0 {
		fmt.Printf("跳过无法解密: %d 个实例（详见下方告警）\n", s.SkippedUnreadable)
	}
	if len(s.Warnings) > 0 {
		fmt.Println("\n[告警]")
		for _, w := range s.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
	if s.RotatingGoogleProfiles > 0 {
		fmt.Println("\n[Google 防风控提醒]")
		fmt.Printf("  1. 检测到 %d 个实例包含 Google 实时轮转会话令牌（PSIDTS/SIDCC）。\n", s.RotatingGoogleProfiles)
		fmt.Println("  2. 导入到另一台电脑并打开后，请勿在旧电脑继续打开同一个 Google 会话，避免双端令牌冲突掉线。")
		fmt.Println("  3. 将本工具 .exe 和该 .antsess 拷贝到目标电脑执行导入即可。")
	}
	fmt.Println()
}

// printImportSummary 打印导入执行结果（或 Dry-Run 预览）、逐实例写入明细与回滚备份路径。
func printImportSummary(s *ImportSummary) {
	title := fmt.Sprintf("导入完成（已通过 %s 重新加密）", platformCryptoLabel())
	if s.DryRun {
		title = "导入预览（Dry-Run，未写入任何文件）"
	}
	fmt.Println("\n============================================================")
	fmt.Printf("  %s\n", title)
	fmt.Println("============================================================")
	fmt.Printf("目标目录:     %s [%s]\n", s.TargetRoot, s.TargetMode)
	fmt.Printf("匹配已有实例: %d 个\n", s.MatchedCount)
	fmt.Printf("新建空壳实例: %d 个\n", s.CreatedCount)
	fmt.Printf("跳过实例:     %d 个\n", s.SkippedCount)
	if !s.DryRun {
		fmt.Printf("写入 Cookie:  %d 条\n", s.TotalCookiesWritten)
		fmt.Printf("恢复存储文件: %d 个\n", s.TotalStorageFiles)
		if s.FingerprintsSynced > 0 {
			fmt.Printf("同步核心指纹: %d 个实例\n", s.FingerprintsSynced)
		}
		if s.ProxiesBound > 0 {
			fmt.Printf("同步代理绑定: %d 个实例（复用目标已有节点 %d 个，新增干净节点 %d 个", s.ProxiesBound, s.ProxyNodesReused, s.ProxyNodesInserted)
			if s.VirtualGroupsSynced > 0 {
				fmt.Printf("，新建虚拟分组 %d 个", s.VirtualGroupsSynced)
			}
			fmt.Println("）")
		}
	}
	if s.BackupRoot != "" {
		fmt.Printf("回滚备份位置: %s\n", s.BackupRoot)
	}

	fmt.Println("\n实例明细：")
	for i, item := range s.Items {
		status := item.Action
		targetDesc := ""
		switch item.Action {
		case "match-id":
			status = "已匹配(ID)"
			targetDesc = fmt.Sprintf("-> 「%s」(%s)", item.TargetProfile.ProfileName, shortID(item.TargetProfile.ProfileID))
		case "match-name":
			status = "已匹配(名称)"
			targetDesc = fmt.Sprintf("-> 「%s」(%s)", item.TargetProfile.ProfileName, shortID(item.TargetProfile.ProfileID))
		case "create":
			status = "新建空壳"
			targetDesc = fmt.Sprintf("-> 「%s」(%s)", item.NewShellProfile.ProfileName, shortID(item.NewShellProfile.ProfileID))
		case "skip-unmatched":
			status = "已跳过"
			targetDesc = item.Detail
		case "skip-ambiguous":
			status = "冲突跳过"
			targetDesc = item.Detail
		}
		var extras []string
		if item.WillSyncFingerprint {
			extras = append(extras, "+指纹")
		}
		if item.WillSyncProxy {
			extras = append(extras, "+代理")
		}
		if item.FingerprintDiff {
			extras = append(extras, "注意:与源实例指纹不同")
		}
		extraTag := ""
		if len(extras) > 0 {
			extraTag = " [" + strings.Join(extras, ", ") + "]"
		}
		fmt.Printf("  %2d. [%-10s] %-22s %s%s\n", i+1, status, item.Source.ProfileName, targetDesc, extraTag)
	}

	if len(s.Warnings) > 0 {
		fmt.Println("\n[告警]")
		for _, w := range s.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}

	fmt.Println("\n[启动前防 Google 风控检查清单]")
	if s.ProxiesBound > 0 && s.ProxiesBound >= (s.MatchedCount+s.CreatedCount) {
		fmt.Println("  1. [已对齐] 已同步源实例代理 IP 绑定；启动前建议确认本机代理连通正常即可。")
	} else {
		fmt.Println("  1. 打开实例前，先确认该实例已配置与原电脑一致（或同地区/同出口）的代理，切勿用本地直连 IP 试探。")
		if s.CreatedCount > 0 {
			fmt.Println("     （新建空壳实例代理已故意留空，Ant Browser 会阻止直连启动，请先选好代理再启动。）")
		}
	}
	if s.FingerprintDiffCount > 0 {
		fmt.Printf("  2. 有 %d 个目标实例的指纹参数与源实例不一致，建议尽量保持同版本 Chromium 内核与相近指纹（或导出/导入时开启指纹同步）。\n", s.FingerprintDiffCount)
	} else if s.FingerprintsSynced > 0 {
		fmt.Println("  2. [已对齐] 已同步源实例核心指纹参数（含确定性种子），请尽量保证 B 机使用同版本 Chromium 内核。")
	}
	if s.RotatingGoogleProfiles > 0 {
		fmt.Println("  3. 本机打开 Google 账号后，请勿再在原电脑并发使用同一账号会话，否则会触发 PSIDTS/SIDCC 轮转冲突。")
	}
	fmt.Println()
}
