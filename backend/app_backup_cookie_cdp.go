package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// cdpGetAllCookies 通过 CDP Network.getAllCookies 获取全量 Cookie（含 HttpOnly/Secure）。
// 使用浏览器级 WebSocket 连接，确保获取所有域的 Cookie。
func cdpGetAllCookies(debugPort int) ([]CookieInfo, error) {
	result, err := cdpCall(debugPort, "Network.getAllCookies", nil)
	if err != nil {
		return nil, fmt.Errorf("CDP Network.getAllCookies 失败: %w", err)
	}

	cookiesRaw, ok := result["cookies"]
	if !ok {
		return []CookieInfo{}, nil
	}

	data, err := json.Marshal(cookiesRaw)
	if err != nil {
		return nil, fmt.Errorf("Cookie 序列化失败: %w", err)
	}
	var cookies []CookieInfo
	if err := json.Unmarshal(data, &cookies); err != nil {
		return nil, fmt.Errorf("Cookie 解析失败: %w", err)
	}
	return cookies, nil
}

// cdpSetCookies 通过 CDP Network.setCookies 批量注入 Cookie。
// 分批注入，每批最多 batchSize 个，避免单次请求过大。
func cdpSetCookies(debugPort int, cookies []CookieInfo) error {
	if len(cookies) == 0 {
		return nil
	}

	const batchSize = 50
	for i := 0; i < len(cookies); i += batchSize {
		end := i + batchSize
		if end > len(cookies) {
			end = len(cookies)
		}
		batch := cookies[i:end]

		cdpCookies := make([]map[string]interface{}, 0, len(batch))
		for _, c := range batch {
			entry := map[string]interface{}{
				"name":   c.Name,
				"value":  c.Value,
				"domain": c.Domain,
				"path":   c.Path,
			}
			if c.Expires > 0 {
				entry["expires"] = c.Expires
			}
			if c.HttpOnly {
				entry["httpOnly"] = true
			}
			if c.Secure {
				entry["secure"] = true
			}
			if c.SameSite != "" {
				entry["sameSite"] = c.SameSite
			}
			// 为 Secure cookie 设置 url 以确保注入成功
			if c.Secure {
				domain := c.Domain
				if strings.HasPrefix(domain, ".") {
					domain = domain[1:]
				}
				entry["url"] = "https://" + domain + c.Path
			}
			cdpCookies = append(cdpCookies, entry)
		}

		params := map[string]interface{}{
			"cookies": cdpCookies,
		}
		if _, err := cdpCall(debugPort, "Network.setCookies", params); err != nil {
			return fmt.Errorf("CDP Network.setCookies 失败 (batch %d-%d): %w", i, end, err)
		}
	}
	return nil
}

// cdpClearAllCookies 通过 CDP 清除浏览器所有 Cookie。
func cdpClearAllCookies(debugPort int) error {
	_, err := cdpCall(debugPort, "Network.clearBrowserCookies", nil)
	if err != nil {
		return fmt.Errorf("CDP Network.clearBrowserCookies 失败: %w", err)
	}
	return nil
}

// cdpCallBrowserLevel 向浏览器级 WebSocket（/json/version）发送 CDP 命令。
// 某些命令需要浏览器级连接（而非 page 级）。
func cdpCallBrowserLevel(debugPort int, method string, params map[string]interface{}) (map[string]interface{}, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", debugPort))
	if err != nil {
		return nil, fmt.Errorf("CDP /json/version 请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var version cdpBrowserVersion
	if err := json.Unmarshal(body, &version); err != nil {
		return nil, fmt.Errorf("CDP browser target 解析失败: %w", err)
	}
	wsURL := strings.TrimSpace(version.WebSocketDebuggerUrl)
	if wsURL == "" {
		return nil, fmt.Errorf("未找到浏览器级 WebSocket 调试地址")
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("浏览器级 WebSocket 连接失败: %w", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	msg := cdpMessage{Id: 1, Method: method, Params: params}
	if err := conn.WriteJSON(msg); err != nil {
		return nil, fmt.Errorf("CDP 命令发送失败: %w", err)
	}

	var cdpResp cdpResponse
	if err := conn.ReadJSON(&cdpResp); err != nil {
		return nil, fmt.Errorf("CDP 响应读取失败: %w", err)
	}
	if cdpResp.Error != nil {
		return nil, fmt.Errorf("CDP 错误: %s", cdpResp.Error.Message)
	}
	return cdpResp.Result, nil
}
