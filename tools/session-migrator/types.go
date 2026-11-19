// types.go 定义迁移工具的核心数据结构，包括 .antsess 归档清单、跨系统 Cookie/指纹/代理快照模型，
// 以及从 Ant Browser 本地数据库读取的实例与安装目录元信息。
package main

const (
	// archiveFormat 标识本工具生成的迁移包格式，防止误导入不兼容的 ZIP 文件。
	archiveFormat = "ant-browser-session-migration"
	// archiveVersion 迁移包格式主版本号。
	archiveVersion = 1
	// archiveExt 默认迁移包文件后缀。
	archiveExt = ".antsess"

	// cookieDBVersionCurrent 对应 Chromium 130+ (含 144) Cookies SQLite 表 schema 版本 24：
	// 该版本在加密 Cookie 明文前追加 32 字节 SHA256(host_key) 用于绑定域名。
	cookieDBVersionCurrent = 24
)

// ArchiveManifest 描述迁移包的公开摘要元数据（绝不含敏感 Cookie、Token、代理账号密码或原始指纹参数）。
type ArchiveManifest struct {
	Format                string                   `json:"format"`
	Version               int                      `json:"version"`
	ToolVersion           string                   `json:"toolVersion"`
	ExportedAt            string                   `json:"exportedAt"`
	SourcePlatform        string                   `json:"sourcePlatform"`
	Encrypted             bool                     `json:"encrypted"`
	KDF                   string                   `json:"kdf,omitempty"`
	IncludeLocalStorage   bool                     `json:"includeLocalStorage"`
	IncludeSessionStorage bool                     `json:"includeSessionStorage"`
	IncludeIndexedDB      bool                     `json:"includeIndexedDB"`
	IncludeFingerprint    bool                     `json:"includeFingerprint,omitempty"`
	IncludeProxy          bool                     `json:"includeProxy,omitempty"`
	ProfileCount          int                      `json:"profileCount"`
	Profiles              []ArchiveProfileMetadata `json:"profiles"`
	Warnings              []string                 `json:"warnings,omitempty"`
}

// ArchiveProfileMetadata 描述单个实例的非敏感摘要信息，用于匹配、预览和风控提醒。
type ArchiveProfileMetadata struct {
	ProfileID               string `json:"profileId"`
	ProfileName             string `json:"profileName"`
	CookieCount             int    `json:"cookieCount"`
	GoogleCookieCount       int    `json:"googleCookieCount"`
	HasRotatingGoogleTokens bool   `json:"hasRotatingGoogleTokens"`
	V20CookieCount          int    `json:"v20CookieCount,omitempty"`
	DBSCSessionCount        int    `json:"dbscSessionCount,omitempty"`
	HasLocalStorage         bool   `json:"hasLocalStorage"`
	HasSessionStorage       bool   `json:"hasSessionStorage"`
	HasIndexedDB            bool   `json:"hasIndexedDB"`
	HasFingerprint          bool   `json:"hasFingerprint,omitempty"`
	HasProxy                bool   `json:"hasProxy,omitempty"`
	ProxySummary            string `json:"proxySummary,omitempty"`
	FingerprintHash         string `json:"fingerprintHash,omitempty"`
	// 仅兼容 v1.0.0 旧包反序列化，v1.1.0+ 新包不再向公开 manifest 写入原始指纹参数。
	LegacyFingerprintArgs []string `json:"fingerprintArgs,omitempty"`
}

// PortableCookieRecord 完整保留 Chromium Cookies SQLite 表的所有 20 列元数据。
type PortableCookieRecord struct {
	CreationUTC          int64  `json:"creationUtc"`
	HostKey              string `json:"hostKey"`
	TopFrameSiteKey      string `json:"topFrameSiteKey"`
	Name                 string `json:"name"`
	Value                string `json:"value"`
	WasPlaintext         bool   `json:"wasPlaintext,omitempty"`
	Path                 string `json:"path"`
	ExpiresUTC           int64  `json:"expiresUtc"`
	IsSecure             int64  `json:"isSecure"`
	IsHTTPOnly           int64  `json:"isHttpOnly"`
	LastAccessUTC        int64  `json:"lastAccessUtc"`
	HasExpires           int64  `json:"hasExpires"`
	IsPersistent         int64  `json:"isPersistent"`
	Priority             int64  `json:"priority"`
	SameSite             int64  `json:"samesite"`
	SourceScheme         int64  `json:"sourceScheme"`
	SourcePort           int64  `json:"sourcePort"`
	LastUpdateUTC        int64  `json:"lastUpdateUtc"`
	SourceType           int64  `json:"sourceType"`
	HasCrossSiteAncestor int64  `json:"hasCrossSiteAncestor"`
}

// ProfileCookieDump 单个实例的解密 Cookie 快照（保存在内层载荷中）。
type ProfileCookieDump struct {
	SchemaVersion int                    `json:"schemaVersion"`
	ProfileID     string                 `json:"profileId"`
	ProfileName   string                 `json:"profileName"`
	Cookies       []PortableCookieRecord `json:"cookies"`
}

// PortableFingerprintDump 单个实例的核心指纹参数快照（仅在启用 --include-fingerprint 时写入内层载荷）。
type PortableFingerprintDump struct {
	ProfileID       string   `json:"profileId"`
	ProfileName     string   `json:"profileName"`
	FingerprintArgs []string `json:"fingerprintArgs"`
}

// PortableProxyNode 最小代理节点定义（仅保留连通与连接栈选择所需的干净字段，不含订阅链接与历史测速记录）。
type PortableProxyNode struct {
	ProxyID         string `json:"proxyId"`
	ProxyName       string `json:"proxyName"`
	ProxyConfig     string `json:"proxyConfig"`
	PreferredKernel string `json:"preferredKernel,omitempty"`
	DNSServers      string `json:"dnsServers,omitempty"`
	GroupName       string `json:"groupName,omitempty"`
}

// PortableVirtualGroup 最小虚拟代理分组定义（仅当被导出实例实际引用时才包含）。
type PortableVirtualGroup struct {
	GroupID          string   `json:"groupId"`
	GroupName        string   `json:"groupName"`
	Strategy         string   `json:"strategy"`
	MemberProxyIDs   []string `json:"memberProxyIds,omitempty"`
	MemberGroupNames []string `json:"memberGroupNames,omitempty"`
}

// PortableProxyDump 单个实例的代理 IP 绑定快照（仅在启用 --include-proxy 时写入内层载荷）。
type PortableProxyDump struct {
	ProfileID      string                `json:"profileId"`
	ProfileName    string                `json:"profileName"`
	ProxyMode      string                `json:"proxyMode"`
	ProxyID        string                `json:"proxyId"`
	ProxyConfig    string                `json:"proxyConfig"`
	ProxyGroupName string                `json:"proxyGroupName,omitempty"`
	ProxyBindName  string                `json:"proxyBindName,omitempty"`
	ReferencedNode *PortableProxyNode    `json:"referencedNode,omitempty"`
	VirtualGroup   *PortableVirtualGroup `json:"virtualGroup,omitempty"`
	MemberNodes    []PortableProxyNode   `json:"memberNodes,omitempty"`
}

// AppProfile 表示从 Ant Browser 的 data/app.db 中读取到的实例元信息。
type AppProfile struct {
	ProfileID       string
	ProfileName     string
	UserDataDir     string
	ResolvedDataDir string
	FingerprintArgs []string
	FingerprintHash string
	ProxyMode       string
	ProxyID         string
	ProxyConfig     string
	ProxyGroupName  string
	ProxyBindName   string
	DeletedAt       string
}

// AppInstallation 表示发现到的 Ant Browser 安装或开发目录。
type AppInstallation struct {
	AppRoot       string
	Mode          string // "dev" | "release"
	ConfigPath    string
	DBPath        string
	UserDataRoot  string
	ActiveCount   int
	DeletedCount  int
	HasAppDB      bool
	DetectedLabel string
}
