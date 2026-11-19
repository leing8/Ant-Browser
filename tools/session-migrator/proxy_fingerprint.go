// proxy_fingerprint.go 实现可选的「核心指纹」与「最小代理 IP 节点」提取与入库协调逻辑：
// - 导出侧：物化确定性指纹种子；仅提取被选中实例实际引用的代理节点或虚拟分组，不导出订阅链接与测速缓存；
// - 导入侧：写入前自动备份 app.db；在单事务中按 proxy_config 去重复用目标节点，遇冲突 ID 自动改号绝不覆盖无关代理。
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

// directProxyID 是 Ant Browser 内置直连节点的保留代理 ID。
const directProxyID = "__direct__"

// normalizeProxyMode 规范化实例代理模式，缺省回退为 fixed。
func normalizeProxyMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "dynamic":
		return "dynamic"
	case "local":
		return "local"
	default:
		return "fixed"
	}
}

// deriveFingerprintSeedFromProfileID 与 Ant Browser 启动期算法一致：
// 若源实例未显式配置 --fingerprint=种子，则在导出指纹时物化出同一确定性种子，
// 确保目标机按名称匹配到不同 profile_id 时依然保持完全一致的 Chromium 指纹种子。
func deriveFingerprintSeedFromProfileID(profileID string) int {
	seed := 0
	for _, ch := range profileID {
		seed = (seed << 5) - seed + int(ch)
	}
	if seed < 0 {
		seed = -seed
	}
	return seed
}

// materializeEffectiveFingerprintArgs 清理空白指纹参数；若未包含 --fingerprint=，
// 则按源 profileID 补齐显式种子，保证跨机匹配不同实例 ID 时浏览器指纹完全一致。
func materializeEffectiveFingerprintArgs(profileID string, rawArgs []string) []string {
	clean := make([]string, 0, len(rawArgs)+1)
	hasSeed := false
	for _, raw := range rawArgs {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		if low == "--fingerprint" || strings.HasPrefix(low, "--fingerprint=") {
			hasSeed = true
		}
		clean = append(clean, t)
	}
	if !hasSeed && strings.TrimSpace(profileID) != "" {
		seedArg := fmt.Sprintf("--fingerprint=%d", deriveFingerprintSeedFromProfileID(strings.TrimSpace(profileID)))
		clean = append([]string{seedArg}, clean...)
	}
	return clean
}

// sourceProxyCatalog 缓存源端代理池与虚拟分组（以只读方式合并 config.yaml 与 app.db），
// 用于导出阶段按需反查被选中实例引用的最小节点定义。
type sourceProxyCatalog struct {
	ProxiesByID       map[string]PortableProxyNode
	VirtualGroupsByID map[string]PortableVirtualGroup
	VirtualGroupsByNm map[string]PortableVirtualGroup
}

// loadSourceProxyCatalog 从源端 config.yaml 与 app.db 只读快照加载代理节点及虚拟分组目录。
func loadSourceProxyCatalog(inst *AppInstallation) (*sourceProxyCatalog, error) {
	cat := &sourceProxyCatalog{
		ProxiesByID:       make(map[string]PortableProxyNode),
		VirtualGroupsByID: make(map[string]PortableVirtualGroup),
		VirtualGroupsByNm: make(map[string]PortableVirtualGroup),
	}

	// 1. 先加载 config.yaml 兜底代理列表（如果存在）
	if raw, err := os.ReadFile(inst.ConfigPath); err == nil {
		var cfg minimalAppConfig
		if yaml.Unmarshal(raw, &cfg) == nil {
			for _, p := range cfg.Browser.Proxies {
				id := strings.TrimSpace(p.ProxyID)
				if id == "" {
					continue
				}
				cat.ProxiesByID[strings.ToLower(id)] = PortableProxyNode{
					ProxyID:         id,
					ProxyName:       strings.TrimSpace(p.ProxyName),
					ProxyConfig:     strings.TrimSpace(p.ProxyConfig),
					PreferredKernel: strings.TrimSpace(p.PreferredKernel),
					DNSServers:      strings.TrimSpace(p.DNSServers),
					GroupName:       strings.TrimSpace(p.GroupName),
				}
			}
		}
	}

	// 2. 再以 app.db 中的 browser_proxies 和 browser_proxy_virtual_groups 为准覆盖
	if !fileExists(inst.DBPath) {
		return cat, nil
	}
	snapshotPath, cleanup, err := snapshotSQLiteToTemp(inst.DBPath)
	if err != nil {
		return nil, fmt.Errorf("创建 app.db 代理快照失败: %w", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("打开 app.db 代理快照失败: %w", err)
	}
	defer db.Close()

	if cols, cErr := tableColumns(db, "browser_proxies"); cErr == nil && len(cols) > 0 {
		colText := func(name string) string {
			if cols[name] {
				return fmt.Sprintf("COALESCE(%s, '')", name)
			}
			return "''"
		}
		q := fmt.Sprintf(`SELECT proxy_id, proxy_name, proxy_config, %s, %s, %s FROM browser_proxies`,
			colText("preferred_kernel"), colText("dns_servers"), colText("group_name"))
		if rows, qErr := db.Query(q); qErr == nil {
			defer rows.Close()
			for rows.Next() {
				var node PortableProxyNode
				if err := rows.Scan(&node.ProxyID, &node.ProxyName, &node.ProxyConfig, &node.PreferredKernel, &node.DNSServers, &node.GroupName); err == nil {
					node.ProxyID = strings.TrimSpace(node.ProxyID)
					node.ProxyName = strings.TrimSpace(node.ProxyName)
					node.ProxyConfig = strings.TrimSpace(node.ProxyConfig)
					node.PreferredKernel = strings.TrimSpace(node.PreferredKernel)
					node.DNSServers = strings.TrimSpace(node.DNSServers)
					node.GroupName = strings.TrimSpace(node.GroupName)
					if node.ProxyID != "" {
						cat.ProxiesByID[strings.ToLower(node.ProxyID)] = node
					}
				}
			}
		}
	}

	if cols, cErr := tableColumns(db, "browser_proxy_virtual_groups"); cErr == nil && len(cols) > 0 {
		colText := func(name string, def string) string {
			if cols[name] {
				return fmt.Sprintf("COALESCE(%s, %s)", name, def)
			}
			return def
		}
		q := fmt.Sprintf(`SELECT %s, %s, %s, %s, %s FROM browser_proxy_virtual_groups`,
			colText("group_id", "''"),
			colText("group_name", "''"),
			colText("strategy", "'round_robin'"),
			colText("member_proxy_ids", "'[]'"),
			colText("member_group_names", "'[]'"),
		)
		if rows, qErr := db.Query(q); qErr == nil {
			defer rows.Close()
			for rows.Next() {
				var vg PortableVirtualGroup
				var memberIDsJSON, memberGroupsJSON string
				if err := rows.Scan(&vg.GroupID, &vg.GroupName, &vg.Strategy, &memberIDsJSON, &memberGroupsJSON); err == nil {
					vg.GroupID = strings.TrimSpace(vg.GroupID)
					vg.GroupName = strings.TrimSpace(vg.GroupName)
					vg.Strategy = strings.TrimSpace(vg.Strategy)
					_ = json.Unmarshal([]byte(memberIDsJSON), &vg.MemberProxyIDs)
					_ = json.Unmarshal([]byte(memberGroupsJSON), &vg.MemberGroupNames)
					if vg.GroupID != "" {
						cat.VirtualGroupsByID[strings.ToLower(vg.GroupID)] = vg
					}
					if vg.GroupName != "" {
						cat.VirtualGroupsByNm[strings.ToLower(vg.GroupName)] = vg
					}
				}
			}
		}
	}

	return cat, nil
}

// buildPortableProxyDump 提取单个实例最干净的代理绑定与被引用节点（不含订阅 URL、测速记录或未引用节点）。
func buildPortableProxyDump(profile AppProfile, cat *sourceProxyCatalog) (*PortableProxyDump, string) {
	mode := normalizeProxyMode(profile.ProxyMode)
	dump := &PortableProxyDump{
		ProfileID:      profile.ProfileID,
		ProfileName:    profile.ProfileName,
		ProxyMode:      mode,
		ProxyID:        strings.TrimSpace(profile.ProxyID),
		ProxyConfig:    strings.TrimSpace(profile.ProxyConfig),
		ProxyGroupName: strings.TrimSpace(profile.ProxyGroupName),
		ProxyBindName:  strings.TrimSpace(profile.ProxyBindName),
	}

	if mode == "dynamic" {
		if dump.ProxyGroupName != "" {
			return dump, "dynamic"
		}
		return dump, "dynamic (pool)"
	}
	if mode == "local" {
		return dump, fmt.Sprintf("local (%s)", extractProxyProtocol(dump.ProxyConfig))
	}

	// fixed 模式
	if strings.EqualFold(dump.ProxyID, directProxyID) || strings.EqualFold(dump.ProxyConfig, "direct://") {
		dump.ProxyID = directProxyID
		dump.ProxyConfig = "direct://"
		if dump.ProxyBindName == "" {
			dump.ProxyBindName = "直连（不走代理）"
		}
		return dump, "direct"
	}

	if cat != nil && dump.ProxyID != "" {
		if node, ok := cat.ProxiesByID[strings.ToLower(dump.ProxyID)]; ok {
			nodeCopy := node
			dump.ReferencedNode = &nodeCopy
			if dump.ProxyConfig == "" {
				dump.ProxyConfig = node.ProxyConfig
			}
			if dump.ProxyBindName == "" {
				dump.ProxyBindName = node.ProxyName
			}
			return dump, fmt.Sprintf("fixed (%s)", extractProxyProtocol(dump.ProxyConfig))
		}
		if vg, ok := cat.VirtualGroupsByID[strings.ToLower(dump.ProxyID)]; ok {
			vgCopy := vg
			dump.VirtualGroup = &vgCopy
			seenMember := make(map[string]bool)
			for _, mid := range vg.MemberProxyIDs {
				key := strings.ToLower(strings.TrimSpace(mid))
				if key == "" || seenMember[key] {
					continue
				}
				if mNode, exists := cat.ProxiesByID[key]; exists {
					seenMember[key] = true
					dump.MemberNodes = append(dump.MemberNodes, mNode)
				}
			}
			return dump, fmt.Sprintf("virtual-group (%d nodes)", len(dump.MemberNodes))
		}
	}

	if dump.ProxyConfig != "" {
		// 节点已不在代理池中，仅保留实例内联的代理配置快照
		return dump, fmt.Sprintf("fixed-inline (%s)", extractProxyProtocol(dump.ProxyConfig))
	}
	return nil, ""
}

// extractProxyProtocol 提取代理 URI 协议头（如 socks5 / vless / hysteria2），仅用于非敏感摘要展示，绝不暴露 IP 或凭据。
func extractProxyProtocol(proxyConfig string) string {
	cfg := strings.TrimSpace(proxyConfig)
	if cfg == "" {
		return "none"
	}
	if idx := strings.Index(cfg, "://"); idx > 0 {
		return strings.ToLower(cfg[:idx])
	}
	return "custom"
}

// profileDBExtraUpdate 描述单个目标实例需要在 app.db 中同步的指纹与代理变更。
type profileDBExtraUpdate struct {
	TargetProfileID string
	SyncFingerprint bool
	FingerprintArgs []string
	SyncProxy       bool
	ProxyDump       *PortableProxyDump
}

// proxySyncStats 汇总一次导入事务中指纹与代理节点的复用/新增计数。
type proxySyncStats struct {
	FingerprintsUpdated int
	ProxiesBound        int
	ProxyNodesReused    int
	ProxyNodesInserted  int
	VirtualGroupsSynced int
}

// backupAppDB 在写入目标 app.db 前自动生成一份干净备份（含配套 -wal/-shm）。
func backupAppDB(dbPath string, backupRoot string) error {
	if backupRoot == "" || !fileExists(dbPath) {
		return nil
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		src := dbPath + suffix
		if fileExists(src) {
			dst := filepath.Join(backupRoot, "app.db"+suffix)
			if err := copyFile(src, dst); err != nil {
				return fmt.Errorf("备份目标 app.db%s 失败: %w", suffix, err)
			}
		}
	}
	return nil
}

// applyProfileExtrasInDB 在单个事务中将可选的核心指纹与最小代理节点干净写入目标 app.db。
// 绝不修改无关配置字段、不写入订阅地址或历史测速缓存、不覆盖目标已有不同配置的代理节点。
func applyProfileExtrasInDB(inst *AppInstallation, updates []profileDBExtraUpdate) (*proxySyncStats, error) {
	stats := &proxySyncStats{}
	if len(updates) == 0 {
		return stats, nil
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", filepath.ToSlash(inst.DBPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开目标数据库失败: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	profileCols, err := tableColumns(db, "browser_profiles")
	if err != nil || len(profileCols) == 0 {
		return nil, fmt.Errorf("读取目标 browser_profiles 表结构失败: %w", err)
	}
	proxyColDetails, _ := tableColumnDetails(db, "browser_proxies")
	vgroupColDetails, _ := tableColumnDetails(db, "browser_proxy_virtual_groups")

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("开启目标数据库事务失败: %w", err)
	}
	defer tx.Rollback()

	// 加载目标机已有代理池用于去重复用（优先按 proxy_config 精确复用，绝不制造重复节点或覆写冲突节点）
	existingByID := make(map[string]PortableProxyNode)
	existingByConfig := make(map[string]PortableProxyNode)
	existingProxyNames := make(map[string]bool)
	maxSortOrder := 0

	if len(proxyColDetails) > 0 {
		rows, qErr := tx.Query(`SELECT proxy_id, proxy_name, proxy_config, COALESCE(sort_order, 0) FROM browser_proxies`)
		if qErr == nil {
			for rows.Next() {
				var n PortableProxyNode
				var sortOrder int
				if rows.Scan(&n.ProxyID, &n.ProxyName, &n.ProxyConfig, &sortOrder) == nil {
					n.ProxyID = strings.TrimSpace(n.ProxyID)
					n.ProxyName = strings.TrimSpace(n.ProxyName)
					n.ProxyConfig = strings.TrimSpace(n.ProxyConfig)
					if n.ProxyID != "" {
						existingByID[strings.ToLower(n.ProxyID)] = n
					}
					if n.ProxyConfig != "" {
						if _, ok := existingByConfig[n.ProxyConfig]; !ok {
							existingByConfig[n.ProxyConfig] = n
						}
					}
					if n.ProxyName != "" {
						existingProxyNames[strings.ToLower(n.ProxyName)] = true
					}
					if sortOrder > maxSortOrder {
						maxSortOrder = sortOrder
					}
				}
			}
			rows.Close()
		}
	}

	now := time.Now().Format(time.RFC3339)

	ensureProxyNode := func(srcNode PortableProxyNode) (PortableProxyNode, error) {
		cfg := strings.TrimSpace(srcNode.ProxyConfig)
		srcID := strings.TrimSpace(srcNode.ProxyID)
		if strings.EqualFold(srcID, directProxyID) || strings.EqualFold(cfg, "direct://") {
			return PortableProxyNode{
				ProxyID:     directProxyID,
				ProxyName:   "直连（不走代理）",
				ProxyConfig: "direct://",
			}, nil
		}

		// 1. 若目标机已有相同 ID 且相同 proxy_config -> 直接复用
		if srcID != "" {
			if ex, ok := existingByID[strings.ToLower(srcID)]; ok && ex.ProxyConfig == cfg {
				stats.ProxyNodesReused++
				return ex, nil
			}
		}
		// 2. 若目标机已有完全相同的 proxy_config -> 直接复用现有节点，避免产生重复节点
		if cfg != "" {
			if ex, ok := existingByConfig[cfg]; ok {
				stats.ProxyNodesReused++
				return ex, nil
			}
		}

		// 若目标库无 browser_proxies 表（极老版本），退回仅在实例上保存 proxy_config 快照
		if len(proxyColDetails) == 0 {
			return srcNode, nil
		}

		// 3. 插入干净的新节点（仅填核心连通字段，不写订阅 URL/测速缓存）
		finalID := srcID
		if finalID == "" || existingByID[strings.ToLower(finalID)].ProxyID != "" {
			finalID = "proxy-migrated-" + strings.ReplaceAll(newRandomUUIDv4(), "-", "")[:12]
		}
		finalName := strings.TrimSpace(srcNode.ProxyName)
		if finalName == "" {
			finalName = "迁移代理-" + shortID(finalID)
		}
		if existingProxyNames[strings.ToLower(finalName)] {
			base := finalName
			for i := 1; ; i++ {
				cand := fmt.Sprintf("%s (迁移)", base)
				if i > 1 {
					cand = fmt.Sprintf("%s (迁移 %d)", base, i)
				}
				if !existingProxyNames[strings.ToLower(cand)] {
					finalName = cand
					break
				}
			}
		}

		maxSortOrder++
		valuesByCol := map[string]any{
			"proxy_id":         finalID,
			"proxy_name":       finalName,
			"proxy_config":     cfg,
			"preferred_kernel": strings.TrimSpace(srcNode.PreferredKernel),
			"dns_servers":      strings.TrimSpace(srcNode.DNSServers),
			"group_name":       strings.TrimSpace(srcNode.GroupName),
			"sort_order":       maxSortOrder,
			"created_at":       now,
		}
		if err := dynamicInsertRow(tx, "browser_proxies", proxyColDetails, valuesByCol); err != nil {
			return PortableProxyNode{}, fmt.Errorf("写入目标代理节点「%s」失败: %w", finalName, err)
		}

		inserted := PortableProxyNode{
			ProxyID:         finalID,
			ProxyName:       finalName,
			ProxyConfig:     cfg,
			PreferredKernel: strings.TrimSpace(srcNode.PreferredKernel),
			DNSServers:      strings.TrimSpace(srcNode.DNSServers),
			GroupName:       strings.TrimSpace(srcNode.GroupName),
		}
		existingByID[strings.ToLower(finalID)] = inserted
		if cfg != "" {
			existingByConfig[cfg] = inserted
		}
		existingProxyNames[strings.ToLower(finalName)] = true
		stats.ProxyNodesInserted++
		return inserted, nil
	}

	// 已有的虚拟分组（用于去重复用）
	existingVGroupsByID := make(map[string]string)   // lower(group_id) -> group_id
	existingVGroupsByName := make(map[string]string) // lower(group_name) -> group_id
	if len(vgroupColDetails) > 0 {
		if rows, qErr := tx.Query(`SELECT COALESCE(group_id,''), COALESCE(group_name,'') FROM browser_proxy_virtual_groups`); qErr == nil {
			for rows.Next() {
				var gid, gname string
				if rows.Scan(&gid, &gname) == nil {
					gid = strings.TrimSpace(gid)
					gname = strings.TrimSpace(gname)
					if gid != "" {
						existingVGroupsByID[strings.ToLower(gid)] = gid
					}
					if gname != "" {
						existingVGroupsByName[strings.ToLower(gname)] = gid
					}
				}
			}
			rows.Close()
		}
	}

	for _, upd := range updates {
		setClauses := make([]string, 0, 8)
		args := make([]any, 0, 8)

		if upd.SyncFingerprint && len(upd.FingerprintArgs) > 0 && profileCols["fingerprint_args"] {
			fpJSON, mErr := json.Marshal(upd.FingerprintArgs)
			if mErr != nil {
				return nil, mErr
			}
			setClauses = append(setClauses, "fingerprint_args = ?")
			args = append(args, string(fpJSON))
			stats.FingerprintsUpdated++
		}

		if upd.SyncProxy && upd.ProxyDump != nil {
			pd := upd.ProxyDump
			mode := normalizeProxyMode(pd.ProxyMode)
			finalProxyID := strings.TrimSpace(pd.ProxyID)
			finalProxyCfg := strings.TrimSpace(pd.ProxyConfig)
			finalBindName := strings.TrimSpace(pd.ProxyBindName)
			finalGroupName := strings.TrimSpace(pd.ProxyGroupName)

			if mode == "fixed" {
				if pd.ReferencedNode != nil {
					resolvedNode, nErr := ensureProxyNode(*pd.ReferencedNode)
					if nErr != nil {
						return nil, nErr
					}
					finalProxyID = resolvedNode.ProxyID
					finalProxyCfg = resolvedNode.ProxyConfig
					finalBindName = resolvedNode.ProxyName
				} else if pd.VirtualGroup != nil && len(vgroupColDetails) > 0 {
					// 同步成员节点与虚拟分组
					mappedMemberIDs := make([]string, 0, len(pd.MemberNodes))
					for _, mn := range pd.MemberNodes {
						rn, nErr := ensureProxyNode(mn)
						if nErr != nil {
							return nil, nErr
						}
						mappedMemberIDs = append(mappedMemberIDs, rn.ProxyID)
					}
					vg := *pd.VirtualGroup
					vgID := strings.TrimSpace(vg.GroupID)
					vgName := strings.TrimSpace(vg.GroupName)
					if hitID, ok := existingVGroupsByID[strings.ToLower(vgID)]; ok {
						finalProxyID = hitID
					} else if hitID, ok := existingVGroupsByName[strings.ToLower(vgName)]; ok {
						finalProxyID = hitID
					} else {
						if vgID == "" {
							vgID = newRandomUUIDv4()
						}
						if vgName == "" {
							vgName = "迁移代理组-" + shortID(vgID)
						}
						memberIDsJSON, _ := json.Marshal(mappedMemberIDs)
						memberGroupsJSON, _ := json.Marshal(vg.MemberGroupNames)
						strategy := strings.TrimSpace(vg.Strategy)
						if strategy == "" {
							strategy = "round_robin"
						}
						vgValues := map[string]any{
							"group_id":           vgID,
							"group_name":         vgName,
							"strategy":           strategy,
							"member_proxy_ids":   string(memberIDsJSON),
							"member_group_names": string(memberGroupsJSON),
							"created_at":         now,
							"updated_at":         now,
						}
						if err := dynamicInsertRow(tx, "browser_proxy_virtual_groups", vgroupColDetails, vgValues); err != nil {
							return nil, fmt.Errorf("写入虚拟代理分组「%s」失败: %w", vgName, err)
						}
						existingVGroupsByID[strings.ToLower(vgID)] = vgID
						existingVGroupsByName[strings.ToLower(vgName)] = vgID
						finalProxyID = vgID
						stats.VirtualGroupsSynced++
					}
					finalProxyCfg = ""
					finalBindName = vgName
				} else if strings.EqualFold(finalProxyID, directProxyID) || strings.EqualFold(finalProxyCfg, "direct://") {
					finalProxyID = directProxyID
					finalProxyCfg = "direct://"
				} else if finalProxyCfg != "" {
					// 内联代理快照：也顺便在代理池中查找或创建干净节点，避免目标机看到“绑定失效”警告
					resolvedNode, nErr := ensureProxyNode(PortableProxyNode{
						ProxyID:     finalProxyID,
						ProxyName:   finalBindName,
						ProxyConfig: finalProxyCfg,
					})
					if nErr != nil {
						return nil, nErr
					}
					finalProxyID = resolvedNode.ProxyID
					finalProxyCfg = resolvedNode.ProxyConfig
					finalBindName = resolvedNode.ProxyName
				}
			}

			if profileCols["proxy_mode"] {
				setClauses = append(setClauses, "proxy_mode = ?")
				args = append(args, mode)
			}
			if profileCols["proxy_id"] {
				setClauses = append(setClauses, "proxy_id = ?")
				args = append(args, finalProxyID)
			}
			if profileCols["proxy_config"] {
				setClauses = append(setClauses, "proxy_config = ?")
				args = append(args, finalProxyCfg)
			}
			if profileCols["proxy_group_name"] {
				setClauses = append(setClauses, "proxy_group_name = ?")
				args = append(args, finalGroupName)
			}
			if profileCols["proxy_bind_name"] {
				setClauses = append(setClauses, "proxy_bind_name = ?")
				args = append(args, finalBindName)
			}
			if profileCols["proxy_bind_source_id"] {
				setClauses = append(setClauses, "proxy_bind_source_id = ''")
			}
			if profileCols["proxy_bind_source_url"] {
				setClauses = append(setClauses, "proxy_bind_source_url = ''")
			}
			if profileCols["proxy_bind_updated_at"] {
				setClauses = append(setClauses, "proxy_bind_updated_at = ?")
				args = append(args, now)
			}
			stats.ProxiesBound++
		}

		if len(setClauses) == 0 {
			continue
		}
		if profileCols["updated_at"] {
			setClauses = append(setClauses, "updated_at = ?")
			args = append(args, now)
		}
		args = append(args, upd.TargetProfileID)
		stmt := fmt.Sprintf("UPDATE browser_profiles SET %s WHERE profile_id = ?", strings.Join(setClauses, ", "))
		if _, err := tx.Exec(stmt, args...); err != nil {
			return nil, fmt.Errorf("更新目标实例 %s 的代理/指纹失败: %w", upd.TargetProfileID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交代理与指纹更新事务失败: %w", err)
	}
	return stats, nil
}

// dynamicInsertRow 根据目标表实际列元信息动态拼装 INSERT 语句，自动为未来新增的 NOT NULL 无默认值列填充安全零值。
func dynamicInsertRow(tx *sql.Tx, tableName string, colDetails []columnDetail, valuesByCol map[string]any) error {
	var cols []string
	var placeholders []string
	var args []any

	for _, ci := range colDetails {
		if val, ok := valuesByCol[ci.name]; ok {
			cols = append(cols, ci.name)
			placeholders = append(placeholders, "?")
			args = append(args, val)
			continue
		}
		if ci.notNull && !ci.hasDefault {
			cols = append(cols, ci.name)
			placeholders = append(placeholders, "?")
			if strings.Contains(strings.ToUpper(ci.colType), "INT") {
				args = append(args, 0)
			} else {
				args = append(args, "")
			}
		}
	}

	stmt := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tableName, strings.Join(cols, ", "), strings.Join(placeholders, ", "))
	_, err := tx.Exec(stmt, args...)
	return err
}
