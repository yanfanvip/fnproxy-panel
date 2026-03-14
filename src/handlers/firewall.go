package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fnproxy/config"
	"fnproxy/models"
	"fnproxy/security"
)

// generateRuleID 生成规则ID
func generateRuleID() string {
	return time.Now().Format("20060102150405") + "-" + fmt.Sprintf("%d", time.Now().Nanosecond())
}

// HandleGetFirewallConfig 获取防火墙配置
func HandleGetFirewallConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	cfg := config.GetManager()
	firewallCfg := cfg.GetFirewallConfig()
	WriteSuccess(w, firewallCfg)
}

// HandleUpdateFirewallConfig 更新防火墙配置
func HandleUpdateFirewallConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	defer r.Body.Close()

	var firewallCfg models.FirewallConfig
	if err := json.Unmarshal(body, &firewallCfg); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	cfg := config.GetManager()
	if err := cfg.UpdateFirewallConfig(firewallCfg); err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to save config: "+err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	action := "停用防火墙"
	if firewallCfg.Enabled {
		action = "启用防火墙"
	}
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, action, "防火墙", action, true, nil)

	WriteSuccess(w, firewallCfg)
}

// HandleAddFirewallRule 添加防火墙规则
func HandleAddFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	defer r.Body.Close()

	var rule models.FirewallRule
	if err := json.Unmarshal(body, &rule); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if rule.Name == "" {
		WriteError(w, http.StatusBadRequest, "Rule name is required")
		return
	}

	if rule.Type == "" {
		rule.Type = models.FirewallRuleTypeIP
	}

	if rule.Action == "" {
		rule.Action = models.FirewallActionAllow
	}

	// 如果没有ID则自动生成
	if rule.ID == "" {
		rule.ID = generateRuleID()
	}

	cfg := config.GetManager()
	if err := cfg.AddFirewallRule(rule); err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to add rule: "+err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "新增防火墙规则", rule.Name, fmt.Sprintf("新增防火墙规则: %s", rule.Name), true, nil)

	WriteSuccess(w, rule)
}

// HandleUpdateFirewallRule 更新防火墙规则
func HandleUpdateFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	path := r.URL.Path
	ruleID := strings.TrimPrefix(path, "/api/firewall/rules/")
	if ruleID == path {
		WriteError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	defer r.Body.Close()

	var rule models.FirewallRule
	if err := json.Unmarshal(body, &rule); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	rule.ID = ruleID

	cfg := config.GetManager()
	if err := cfg.UpdateFirewallRule(rule); err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to update rule: "+err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "更新防火墙规则", rule.Name, fmt.Sprintf("更新防火墙规则: %s", rule.Name), true, nil)

	WriteSuccess(w, rule)
}

// HandleDeleteFirewallRule 删除防火墙规则
func HandleDeleteFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	path := r.URL.Path
	ruleID := strings.TrimPrefix(path, "/api/firewall/rules/")
	if ruleID == path {
		WriteError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	cfg := config.GetManager()

	// 先取出规则名称，用于日志记录
	ruleName := ruleID
	if fw := cfg.GetFirewallConfig(); fw != nil {
		for _, r := range fw.Rules {
			if r.ID == ruleID {
				ruleName = r.Name
				break
			}
		}
	}

	if err := cfg.DeleteFirewallRule(ruleID); err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to delete rule: "+err.Error())
		return
	}

	// 记录安全日志
	opUser, opAddr := getRequestContext(r)
	security.GetAuditLogger().LogSystemOperate(opUser, opAddr, "删除防火墙规则", ruleName, fmt.Sprintf("删除防火墙规则: %s", ruleName), true, nil)

	WriteSuccess(w, nil)
}
