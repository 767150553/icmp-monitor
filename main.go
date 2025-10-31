package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"os/exec"
	"runtime"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strconv"
)

// Event 表示一个 ICMP 事件
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	Type      string    `json:"type"`
	Size      int       `json:"size"`
}

// SourceStat 表示来源主机的统计信息
type SourceStat struct {
	IP         string    `json:"ip"`
	Count      int       `json:"count"`
	TotalBytes int       `json:"total_bytes"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// 防御配置
type DefenseConfig struct {
	RateLimitPerSecond int           `json:"rate_limit_per_second"`
	RateLimitPerMinute int           `json:"rate_limit_per_minute"`
	BurstPerSecond     int           `json:"burst_per_second"`
	BlacklistDuration  time.Duration `json:"blacklist_duration"`
	AlertThreshold     int           `json:"alert_threshold"`
	EnableSound        bool          `json:"enable_sound"`
	Whitelist          []string      `json:"whitelist"`
	MaxPacketSize      int           `json:"max_packet_size"` // 0 表示关闭大小检查
	EnableFirewall     bool          `json:"enable_firewall"`
}


// 动态防御配置更新（增量）
type DefenseConfigUpdate struct {
	RateLimitPerSecond *int `json:"rate_limit_per_second,omitempty"`
	RateLimitPerMinute *int `json:"rate_limit_per_minute,omitempty"`
	BurstPerSecond     *int `json:"burst_per_second,omitempty"`
	BlacklistDurationSeconds *int `json:"blacklist_duration_seconds,omitempty"`
	AlertThreshold *int `json:"alert_threshold,omitempty"`
	EnableSound *bool `json:"enable_sound,omitempty"`
	Whitelist *[]string `json:"whitelist,omitempty"`
	MaxPacketSize *int `json:"max_packet_size,omitempty"`
	EnableFirewall *bool `json:"enable_firewall,omitempty"`
}

// 分片锁结构
type ShardedMap struct {
	shards []map[string]interface{}
	locks  []sync.RWMutex
	size   int
}

func NewShardedMap(shardCount int) *ShardedMap {
	return &ShardedMap{
		shards: make([]map[string]interface{}, shardCount),
		locks:  make([]sync.RWMutex, shardCount),
		size:   shardCount,
	}
}

func (sm *ShardedMap) getShard(key string) (int, *map[string]interface{}, *sync.RWMutex) {
	hash := 0
	for _, c := range key {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	idx := hash % sm.size
	if sm.shards[idx] == nil {
		sm.shards[idx] = make(map[string]interface{})
	}
	return idx, &sm.shards[idx], &sm.locks[idx]
}

func (sm *ShardedMap) Get(key string) (interface{}, bool) {
	_, shard, lock := sm.getShard(key)
	lock.RLock()
	defer lock.RUnlock()
	val, ok := (*shard)[key]
	return val, ok
}

func (sm *ShardedMap) Set(key string, value interface{}) {
	_, shard, lock := sm.getShard(key)
	lock.Lock()
	defer lock.Unlock()
	(*shard)[key] = value
}

func (sm *ShardedMap) Delete(key string) {
	_, shard, lock := sm.getShard(key)
	lock.Lock()
	defer lock.Unlock()
	delete(*shard, key)
}

func (sm *ShardedMap) Range(fn func(key, value interface{}) bool) {
	for i := 0; i < sm.size; i++ {
		sm.locks[i].RLock()
		if sm.shards[i] != nil {
			for k, v := range sm.shards[i] {
				if !fn(k, v) {
					sm.locks[i].RUnlock()
					return
				}
			}
		}
		sm.locks[i].RUnlock()
	}
}

// 频率限制器
type RateLimiter struct {
	// 使用分片锁提高并发性能
	tokens        *ShardedMap          // 当前令牌数
	lastRefill    *ShardedMap          // 上次补充时间（按秒）
	secondCounts  *ShardedMap          // 当前秒内计数
	lastSecond    *ShardedMap          // 上次秒级重置时间
	minuteCounts  *ShardedMap          // 每分钟计数
	lastMinute    *ShardedMap          // 上次分钟级重置时间
	blacklist     *ShardedMap          // 黑名单（IP -> 解封时间）
	blockedReasons *ShardedMap         // 黑名单原因
	alertHistory  *ShardedMap          // 告警历史
	blockedCounts *ShardedMap          // 被阻止请求计数
	lastSeen      *ShardedMap          // 最近一次活跃时间（用于清理）
	janitorStop   chan struct{}        // 清理器停止信号
	
	// 全局统计（使用原子操作）
	blockedTotal  int64                // 被阻止请求总数（原子操作）
	config        DefenseConfig
	configMu      sync.RWMutex         // 配置锁
}

func NewRateLimiter(config DefenseConfig) *RateLimiter {
	// 默认突发容量等于每秒限制
	if config.BurstPerSecond <= 0 {
		config.BurstPerSecond = config.RateLimitPerSecond
	}
	
	// 使用16个分片，在性能和内存之间平衡
	shardCount := 16
	
	rl := &RateLimiter{
		tokens:        NewShardedMap(shardCount),
		lastRefill:    NewShardedMap(shardCount),
		secondCounts:  NewShardedMap(shardCount),
		lastSecond:    NewShardedMap(shardCount),
		minuteCounts:  NewShardedMap(shardCount),
		lastMinute:    NewShardedMap(shardCount),
		blacklist:     NewShardedMap(shardCount),
		blockedReasons: NewShardedMap(shardCount),
		alertHistory:  NewShardedMap(shardCount),
		blockedCounts: NewShardedMap(shardCount),
		lastSeen:      NewShardedMap(shardCount),
		janitorStop:   make(chan struct{}),
		config:        config,
	}
// 启动清理器
rl.startJanitor()
return rl
}

// 标记IP最近活跃时间
func (rl *RateLimiter) markSeen(ip string) {
	rl.lastSeen.Set(ip, time.Now())
}

// 清理过期键，避免内存泄漏
func (rl *RateLimiter) cleanupStale(now time.Time, retention time.Duration) {
	// 遍历lastSeen，删除长时间未活跃的普通计数与令牌，不动黑名单
	rl.lastSeen.Range(func(key, value interface{}) bool {
		ip, ok := key.(string)
		if !ok { return true }
		last, ok := value.(time.Time)
		if !ok { return true }
		if now.Sub(last) > retention {
			// 删除各类映射项
			rl.tokens.Delete(ip)
			rl.lastRefill.Delete(ip)
			rl.secondCounts.Delete(ip)
			rl.lastSecond.Delete(ip)
			rl.minuteCounts.Delete(ip)
			rl.lastMinute.Delete(ip)
			rl.blockedCounts.Delete(ip)
			// 最后删除lastSeen自身
			rl.lastSeen.Delete(ip)
		}
		return true
	})
}

// 启动后台清理器（每分钟清理一次，保留期20分钟）
func (rl *RateLimiter) startJanitor() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		retention := 20 * time.Minute
		for {
			select {
			case <-ticker.C:
				rl.cleanupStale(time.Now(), retention)
			case <-rl.janitorStop:
				return
			}
		}
	}()
}

// 停止清理器
func (rl *RateLimiter) StopJanitor() { close(rl.janitorStop) }

// 检查IP是否在白名单中
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	rl.configMu.RLock()
	whitelist := rl.config.Whitelist
	rl.configMu.RUnlock()
	
	for _, whiteIP := range whitelist {
		if ip == whiteIP {
			return true
		}
	}
	return false
}

// 检查IP是否被黑名单阻止（同时清理过期项）
func (rl *RateLimiter) isBlacklisted(ip string) bool {
	if val, exists := rl.blacklist.Get(ip); exists {
		if unblockTime, ok := val.(time.Time); ok {
			if time.Now().Before(unblockTime) {
				return true
			}
			// 黑名单过期，删除并同步移除防火墙规则（如启用）
			rl.blacklist.Delete(ip)
			rl.blockedReasons.Delete(ip)
			
			rl.configMu.RLock()
			enableFirewall := rl.config.EnableFirewall
			rl.configMu.RUnlock()
			
			if enableFirewall && runtime.GOOS == "windows" {
				go removeFirewallRulesForIP(ip)
			}
		}
	}
	return false
}

// 记录一次阻止
func (rl *RateLimiter) incrementBlocked(ip string) {
	// 使用原子操作更新总数
	atomic.AddInt64(&rl.blockedTotal, 1)
	
	// 更新IP计数
	if val, exists := rl.blockedCounts.Get(ip); exists {
		if count, ok := val.(int); ok {
			rl.blockedCounts.Set(ip, count+1)
		} else {
			rl.blockedCounts.Set(ip, 1)
		}
	} else {
		rl.blockedCounts.Set(ip, 1)
	}
}

// 添加到黑名单
func (rl *RateLimiter) addToBlacklist(ip string) {
	rl.configMu.RLock()
	duration := rl.config.BlacklistDuration
	enableFirewall := rl.config.EnableFirewall
	rl.configMu.RUnlock()
	
	until := time.Now().Add(duration)
	rl.blacklist.Set(ip, until)
	log.Printf("🚫 [防御] IP %s 已加入黑名单，持续时间: %v", ip, duration)
	
	// 若启用系统防火墙，并且运行在 Windows，尝试添加阻止规则
	if enableFirewall && runtime.GOOS == "windows" {
		go addFirewallRulesForIP(ip)
	}
}

// 安全验证IP地址格式
func isValidIP(ip string) bool {
	if len(ip) == 0 || len(ip) > 45 { // IPv6最长39字符，留点余量
		return false
	}
	
	// 使用标准库验证
	if net.ParseIP(ip) == nil {
		return false
	}
	
	// 额外正则验证防止边界情况
	return ipv4Regex.MatchString(ip) || ipv6Regex.MatchString(ip)
}

// 安全转义PowerShell参数
func escapePowerShellArg(arg string) string {
	// 移除潜在危险字符
	arg = strings.ReplaceAll(arg, "'", "")
	arg = strings.ReplaceAll(arg, "\"", "")
	arg = strings.ReplaceAll(arg, ";", "")
	arg = strings.ReplaceAll(arg, "&", "")
	arg = strings.ReplaceAll(arg, "|", "")
	arg = strings.ReplaceAll(arg, "`", "")
	arg = strings.ReplaceAll(arg, "$", "")
	arg = strings.ReplaceAll(arg, "(", "")
	arg = strings.ReplaceAll(arg, ")", "")
	return arg
}

// 执行防火墙 PowerShell 命令并记录结果
func runFirewallCmd(ps string) error {
	// 限制命令长度防止过长命令
	if len(ps) > 500 {
		err := fmt.Errorf("命令过长，可能存在安全风险")
		firewallStatusMu.Lock()
		firewallLastStatus = fmt.Sprintf("失败: %v", err)
		firewallStatusMu.Unlock()
		log.Printf("[防火墙] 命令被拒绝: 长度超限")
		return err
	}
	
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	out, err := cmd.CombinedOutput()
	firewallStatusMu.Lock()
	if err != nil {
		firewallLastStatus = fmt.Sprintf("失败: %v; 输出: %s", err, strings.TrimSpace(string(out)))
	} else {
		firewallLastStatus = "成功"
	}
	firewallStatusMu.Unlock()
	if err != nil {
		log.Printf("[防火墙] 执行失败: %s; 错误: %v; 输出: %s", ps, err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[防火墙] 已执行: %s", ps)
	}
	return err
}

// 添加 Windows 防火墙规则以阻止指定 IP 的 ICMPv4/ICMPv6
func addFirewallRulesForIP(ip string) {
	// 严格验证IP地址
	if !isValidIP(ip) {
		log.Printf("[防火墙] 无效IP地址，拒绝添加规则: %s", ip)
		firewallStatusMu.Lock()
		firewallLastStatus = fmt.Sprintf("失败: 无效IP地址 %s", ip)
		firewallStatusMu.Unlock()
		return
	}
	
	// 安全转义IP地址
	safeIP := escapePowerShellArg(ip)
	
	// 构建安全的PowerShell命令
	ps1 := fmt.Sprintf("New-NetFirewallRule -DisplayName 'ICMP Block %s v4' -Direction Inbound -Action Block -RemoteAddress '%s' -Protocol ICMPv4 -IcmpType 8 -Profile Any -Enabled True", safeIP, safeIP)
	_ = runFirewallCmd(ps1)
	
	ps2 := fmt.Sprintf("New-NetFirewallRule -DisplayName 'ICMP Block %s v6' -Direction Inbound -Action Block -RemoteAddress '%s' -Protocol ICMPv6 -IcmpType 128 -Profile Any -Enabled True", safeIP, safeIP)
	_ = runFirewallCmd(ps2)
}

// 移除 Windows 防火墙中针对指定 IP 的阻止规则
func removeFirewallRulesForIP(ip string) {
	// 严格验证IP地址
	if !isValidIP(ip) {
		log.Printf("[防火墙] 无效IP地址，拒绝移除规则: %s", ip)
		firewallStatusMu.Lock()
		firewallLastStatus = fmt.Sprintf("失败: 无效IP地址 %s", ip)
		firewallStatusMu.Unlock()
		return
	}
	
	// 安全转义IP地址
	safeIP := escapePowerShellArg(ip)
	
	// 使用更安全的删除方式
	ps := fmt.Sprintf("Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'ICMP Block %s *'} | Remove-NetFirewallRule -Confirm:$false", safeIP)
	_ = runFirewallCmd(ps)
}

// 发送告警
func (rl *RateLimiter) sendAlert(ip string, count int, timeframe string) {
    // 避免重复告警（5分钟内同一IP只告警一次）
    if val, exists := rl.alertHistory.Get(ip); exists {
        if lastAlert, ok := val.(time.Time); ok {
            if time.Since(lastAlert) < 5*time.Minute {
                return
            }
        }
    }
    rl.alertHistory.Set(ip, time.Now())
    alertMsg := fmt.Sprintf("🚨 [攻击告警] 检测到来自 %s 的可疑活动: %s内 %d 次请求", ip, timeframe, count)
    log.Println(alertMsg)
    
    rl.configMu.RLock()
    enableSound := rl.config.EnableSound
    rl.configMu.RUnlock()
    
    if enableSound {
        go func() { fmt.Print("\a") }()
    }
}

// 检查并更新频率限制（令牌桶 + 分钟计数）
func (rl *RateLimiter) checkRateLimit(ip string) bool {
	// 标记活跃
	rl.markSeen(ip)
	// 白名单IP跳过检查
	if rl.isWhitelisted(ip) { return true }

	// 黑名单IP直接拒绝
	if rl.isBlacklisted(ip) {
		rl.incrementBlocked(ip)
		return false
	}

	now := time.Now()
	
	// 获取配置（使用读锁）
	rl.configMu.RLock()
	burstPerSecond := rl.config.BurstPerSecond
	rateLimitPerSecond := rl.config.RateLimitPerSecond
	rateLimitPerMinute := rl.config.RateLimitPerMinute
	alertThreshold := rl.config.AlertThreshold
	rl.configMu.RUnlock()

	// 秒级计数仅用于告警阈值
	var secondCount int
	if val, exists := rl.lastSecond.Get(ip); !exists {
		rl.secondCounts.Set(ip, 1)
		rl.lastSecond.Set(ip, now)
		secondCount = 1
	} else {
		if lastSec, ok := val.(time.Time); ok && now.Sub(lastSec) >= time.Second {
			rl.secondCounts.Set(ip, 1)
			rl.lastSecond.Set(ip, now)
			secondCount = 1
		} else {
			if countVal, exists := rl.secondCounts.Get(ip); exists {
				if count, ok := countVal.(int); ok {
					secondCount = count + 1
					rl.secondCounts.Set(ip, secondCount)
				} else {
					secondCount = 1
					rl.secondCounts.Set(ip, secondCount)
				}
			} else {
				secondCount = 1
				rl.secondCounts.Set(ip, secondCount)
			}
		}
	}

	// 分钟级计数重置与累加
	var minuteCount int
	if val, exists := rl.lastMinute.Get(ip); !exists {
		rl.minuteCounts.Set(ip, 1)
		rl.lastMinute.Set(ip, now)
		minuteCount = 1
	} else {
		if lastMin, ok := val.(time.Time); ok && now.Sub(lastMin) >= time.Minute {
			rl.minuteCounts.Set(ip, 1)
			rl.lastMinute.Set(ip, now)
			minuteCount = 1
		} else {
			if countVal, exists := rl.minuteCounts.Get(ip); exists {
				if count, ok := countVal.(int); ok {
					minuteCount = count + 1
					rl.minuteCounts.Set(ip, minuteCount)
				} else {
					minuteCount = 1
					rl.minuteCounts.Set(ip, minuteCount)
				}
			} else {
				minuteCount = 1
				rl.minuteCounts.Set(ip, minuteCount)
			}
		}
	}

	// 令牌桶补充
	var tokens int
	if val, exists := rl.lastRefill.Get(ip); !exists {
		tokens = burstPerSecond - 1 // 消耗一个令牌
		rl.tokens.Set(ip, tokens)
		rl.lastRefill.Set(ip, now)
	} else {
		if lastRefill, ok := val.(time.Time); ok {
			elapsed := now.Sub(lastRefill)
			if elapsed >= time.Second {
				add := int(elapsed/time.Second) * rateLimitPerSecond
				if tokenVal, exists := rl.tokens.Get(ip); exists {
					if t, ok := tokenVal.(int); ok {
						tokens = t + add
					} else {
						tokens = add
					}
				} else {
					tokens = add
				}
				if tokens > burstPerSecond { 
					tokens = burstPerSecond 
				}
				tokens-- // 消耗一个令牌
				rl.tokens.Set(ip, tokens)
				steps := int(elapsed / time.Second)
				rl.lastRefill.Set(ip, lastRefill.Add(time.Duration(steps) * time.Second))
			} else {
				// 消耗令牌
				if tokenVal, exists := rl.tokens.Get(ip); exists {
					if t, ok := tokenVal.(int); ok {
						tokens = t - 1
						rl.tokens.Set(ip, tokens)
					} else {
						tokens = -1
						rl.tokens.Set(ip, tokens)
					}
				} else {
					tokens = -1
					rl.tokens.Set(ip, tokens)
				}
			}
		} else {
			tokens = burstPerSecond - 1
			rl.tokens.Set(ip, tokens)
			rl.lastRefill.Set(ip, now)
		}
	}

	// 检查秒级令牌不足 => 加黑名单
	if tokens < 0 {
		rl.sendAlert(ip, secondCount, "1秒")
		rl.blockedReasons.Set(ip, "rate_sec")
		rl.addToBlacklist(ip)
		rl.incrementBlocked(ip)
		return false
	}

	// 检查分钟级限制
	if minuteCount > rateLimitPerMinute {
		rl.sendAlert(ip, minuteCount, "1分钟")
		rl.blockedReasons.Set(ip, "rate_min")
		rl.addToBlacklist(ip)
		rl.incrementBlocked(ip)
		return false
	}

	// 告警阈值（不阻止）
	if secondCount >= alertThreshold {
		rl.sendAlert(ip, secondCount, "1秒")
	}
	return true
}

// 检查包大小（超限则拉黑并阻止）
func (rl *RateLimiter) CheckSize(ip string, size int) bool {
	// 标记活跃
	rl.markSeen(ip)
	// 白名单IP跳过检查
	if rl.isWhitelisted(ip) {
		return true
	}
	// 黑名单IP直接拒绝
	if rl.isBlacklisted(ip) {
		rl.incrementBlocked(ip)
		return false
	}
	// 检查大小限制
	rl.configMu.RLock()
	maxPacketSize := rl.config.MaxPacketSize
	rl.configMu.RUnlock()
	
	if maxPacketSize > 0 && size > maxPacketSize {
		rl.blockedReasons.Set(ip, "size_max")
		rl.addToBlacklist(ip)
		rl.incrementBlocked(ip)
		return false
	}
	return true
}

// 获取防御统计信息
func (rl *RateLimiter) getDefenseStats() map[string]interface{} {
	activeBlacklist := make([]string, 0)
	entries := make([]map[string]interface{}, 0)
	
	// 遍历黑名单（使用分片锁的迭代器）
	rl.blacklist.Range(func(key, value interface{}) bool {
		if ip, ok := key.(string); ok {
			if unblockTime, ok := value.(time.Time); ok {
				if time.Now().Before(unblockTime) {
					activeBlacklist = append(activeBlacklist, ip)
					rem := int(time.Until(unblockTime).Seconds())
					if rem < 0 { rem = 0 }
					
					var reason string
					if reasonVal, exists := rl.blockedReasons.Get(ip); exists {
						if r, ok := reasonVal.(string); ok {
							reason = r
						}
					}
					entries = append(entries, map[string]interface{}{
						"ip": ip, 
						"remaining_seconds": rem, 
						"reason": reason,
					})
				}
			}
		}
		return true // 继续迭代
	})

	// 复制被阻止计数（避免直接暴露内部引用）
	blockedCopy := make(map[string]int)
	rl.blockedCounts.Range(func(key, value interface{}) bool {
		if ip, ok := key.(string); ok {
			if count, ok := value.(int); ok {
				blockedCopy[ip] = count
			}
		}
		return true
	})
	
	// 读取配置（使用读锁）
	rl.configMu.RLock()
	config := rl.config
	rl.configMu.RUnlock()
	
	// 读取最近一次防火墙命令状态（带锁）
	firewallStatusMu.Lock()
	fwStatus := firewallLastStatus
	firewallStatusMu.Unlock()

	return map[string]interface{}{
		"blacklisted_ips":    activeBlacklist,
		"blacklist_entries":  entries,
		"blacklist_count":    len(activeBlacklist),
		"whitelist":          config.Whitelist,
		"rate_limit_second":  config.RateLimitPerSecond,
		"rate_limit_minute":  config.RateLimitPerMinute,
		"burst_per_second":   config.BurstPerSecond,
		"alert_threshold":    config.AlertThreshold,
		"blacklist_duration": config.BlacklistDuration.String(),
		"enable_sound":       config.EnableSound,
		"max_packet_size":    config.MaxPacketSize,
		"enable_firewall":    config.EnableFirewall,
		"blocked_counts":     blockedCopy,
		"blocked_total":      atomic.LoadInt64(&rl.blockedTotal),
		"firewall_status":    fwStatus,
	}
}

// 清空黑名单（保留阻止计数）
func (rl *RateLimiter) ClearBlacklist() {
	// 收集需要清理的IP
	var ipsToRemove []string
	rl.blacklist.Range(func(key, value interface{}) bool {
		if ip, ok := key.(string); ok {
			ipsToRemove = append(ipsToRemove, ip)
		}
		return true
	})
	
	// 获取防火墙配置
	rl.configMu.RLock()
	enableFirewall := rl.config.EnableFirewall
	rl.configMu.RUnlock()
	
	// 清理黑名单和原因
	for _, ip := range ipsToRemove {
		rl.blacklist.Delete(ip)
		rl.blockedReasons.Delete(ip)
		// 如启用防火墙，则同步移除 Windows 防火墙规则
		if enableFirewall && runtime.GOOS == "windows" {
			go removeFirewallRulesForIP(ip)
		}
	}
}

// 动态更新防御配置（仅更新提供的字段）
func (rl *RateLimiter) UpdateConfig(update DefenseConfigUpdate) {
	rl.configMu.Lock()
	defer rl.configMu.Unlock()
	
	if update.RateLimitPerSecond != nil {
		rl.config.RateLimitPerSecond = *update.RateLimitPerSecond
	}
	if update.RateLimitPerMinute != nil {
		rl.config.RateLimitPerMinute = *update.RateLimitPerMinute
	}
	if update.BurstPerSecond != nil {
		rl.config.BurstPerSecond = *update.BurstPerSecond
	}
	if update.BlacklistDurationSeconds != nil {
		rl.config.BlacklistDuration = time.Duration(*update.BlacklistDurationSeconds) * time.Second
	}
	if update.AlertThreshold != nil {
		rl.config.AlertThreshold = *update.AlertThreshold
	}
	if update.EnableSound != nil {
		rl.config.EnableSound = *update.EnableSound
	}
	if update.Whitelist != nil {
		// 复制切片以避免外部引用影响内部
		wl := make([]string, 0, len(*update.Whitelist))
		for _, ip := range *update.Whitelist {
			wl = append(wl, strings.TrimSpace(ip))
		}
		rl.config.Whitelist = wl
	}
	if update.MaxPacketSize != nil {
		v := *update.MaxPacketSize
		if v < 0 { v = 0 }
		rl.config.MaxPacketSize = v
	}
	if update.EnableFirewall != nil {
		oldFirewall := rl.config.EnableFirewall
		rl.config.EnableFirewall = *update.EnableFirewall
		
		// 当切换防火墙开关时，与当前黑名单同步规则
		if runtime.GOOS == "windows" && oldFirewall != *update.EnableFirewall {
			if *update.EnableFirewall {
				// 启用防火墙：为所有活跃黑名单IP添加规则
				rl.blacklist.Range(func(key, value interface{}) bool {
					if ip, ok := key.(string); ok {
						if until, ok := value.(time.Time); ok {
							if time.Now().Before(until) {
								go addFirewallRulesForIP(ip)
							}
						}
					}
					return true
				})
			} else {
				// 禁用防火墙：移除所有黑名单IP的规则
				rl.blacklist.Range(func(key, value interface{}) bool {
					if ip, ok := key.(string); ok {
						go removeFirewallRulesForIP(ip)
					}
					return true
				})
			}
		}
	}
}

var (
	mu           sync.RWMutex
	events       []Event
	sourceStats  map[string]*SourceStat
	rateLimiter  *RateLimiter
	// 认证失败计数与时间窗口
	authFailCounts = NewShardedMap(16)
	authLastWindow = NewShardedMap(16)
	// 认证配置
	authToken    string
	authUser     string
	// TLS证书路径
	tlsCertPath  string
	tlsKeyPath   string
	// 防火墙状态（记录最近一次命令的执行结果）
	firewallStatusMu  sync.Mutex
	firewallLastStatus string
	// IP验证正则表达式
	ipv4Regex = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	ipv6Regex = regexp.MustCompile(`^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$`)
)

func getRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func main() {
	var (
		interfaceFilter = flag.String("interface", "", "指定网卡名称（为空则监控所有活跃网卡）")
		jsonOutput      = flag.Bool("json", false, "输出 JSON 格式")
		duration        = flag.Duration("duration", 0, "运行时长（0 表示持续运行）")
		summaryInterval = flag.Duration("summary", 30*time.Second, "汇总输出间隔")
		debugMode       = flag.Bool("debug", false, "启用调试模式")
		webAddr         = flag.String("web", "", "启用 Web UI（例：:8080）")
		qtMode          = flag.Bool("qt", false, "启用 Qt 桌面 GUI")
		includeLo       = flag.Bool("include-lo", false, "包含 loopback 设备抓取")
		useAny          = flag.Bool("use-any", false, "使用 'any' 设备抓取（Linux）")
		// 防御参数
		rateLimitSec    = flag.Int("rate-limit-sec", 10, "每秒最大ICMP请求数")
		rateLimitMin    = flag.Int("rate-limit-min", 100, "每分钟最大ICMP请求数")
		blacklistTime   = flag.Duration("blacklist-time", 10*time.Minute, "黑名单持续时间")
		alertThreshold  = flag.Int("alert-threshold", 5, "告警阈值（每秒请求数）")
		enableSound     = flag.Bool("sound-alert", false, "启用声音告警")
		whitelistIPs    = flag.String("whitelist", "", "白名单IP列表（逗号分隔）")
		webToken        = flag.String("web-token", "", "Web API 认证令牌（可选）")
		webUser         = flag.String("web-user", "", "Web 认证用户名（可选）")
		tlsCert         = flag.String("tls-cert", "", "TLS 证书文件路径（启用 HTTPS）")
		tlsKey          = flag.String("tls-key", "", "TLS 私钥文件路径（启用 HTTPS）")
	)
	flag.Parse()
	authToken = *webToken
	authUser = strings.TrimSpace(*webUser)
	tlsCertPath = strings.TrimSpace(*tlsCert)
	tlsKeyPath = strings.TrimSpace(*tlsKey)

	// 初始化防御配置
	defenseConfig := DefenseConfig{
		RateLimitPerSecond: *rateLimitSec,
		RateLimitPerMinute: *rateLimitMin,
		BlacklistDuration:  *blacklistTime,
		AlertThreshold:     *alertThreshold,
		EnableSound:        *enableSound,
		Whitelist:          []string{},
	}
	
	if *whitelistIPs != "" {
		defenseConfig.Whitelist = strings.Split(*whitelistIPs, ",")
		for i, ip := range defenseConfig.Whitelist {
			defenseConfig.Whitelist[i] = strings.TrimSpace(ip)
		}
	}
	
	rateLimiter = NewRateLimiter(defenseConfig)
	sourceStats = make(map[string]*SourceStat)

	fmt.Println("[提示] Windows 需安装 Npcap 并以管理员运行；Linux 建议以 root 或给二进制授予 cap_net_raw,cap_net_admin 能力。")
	fmt.Println("       Linux 例：sudo setcap cap_net_raw,cap_net_admin=eip ./icmp-monitor 或直接 sudo 运行")
	fmt.Printf("🛡️ [防御] 已启用防御功能 - 每秒限制: %d, 每分钟限制: %d, 黑名单时长: %v\n", 
		*rateLimitSec, *rateLimitMin, *blacklistTime)

	// 启动 Qt GUI
	if *qtMode {
		startQtUI()
		return
	}

	// 启动 Web UI
	if *webAddr != "" {
		bindAddr := *webAddr
		if strings.HasPrefix(bindAddr, ":") {
			bindAddr = "127.0.0.1" + bindAddr
		}
		go startWebServer(bindAddr)
		fmt.Printf("Web UI listening: http://%s/\n", bindAddr)
	}

	// 获取所有网络设备
	devices, err := pcap.FindAllDevs()
	if err != nil { log.Fatal(err) }
	var wg sync.WaitGroup
	for _, device := range devices {
		if device.Name == "any" && !*useAny { continue }
		if isLoopbackDevice(device) && !*includeLo { continue }
		if *interfaceFilter != "" && !strings.Contains(device.Name, *interfaceFilter) { continue }
		localIPs := getLocalIPs(device)
		if len(localIPs) == 0 { continue }
		wg.Add(1)
		go func(dev pcap.Interface, ips []string) { defer wg.Done(); captureOnDevice(dev, ips, *debugMode) }(device, localIPs)
	}

	// 设置运行时长
	if *duration > 0 {
		go func() {
			time.Sleep(*duration)
			os.Exit(0)
		}()
	}

	// 定期输出汇总
	go func() {
		ticker := time.NewTicker(*summaryInterval)
		defer ticker.Stop()
		for range ticker.C {
			printSummary(*jsonOutput)
		}
	}()

	wg.Wait()
}

func getLocalIPs(device pcap.Interface) []string {
	var ips []string
	for _, addr := range device.Addresses {
		if addr.IP != nil {
			ips = append(ips, addr.IP.String())
		}
	}
	return ips
}

func getDeviceDescription(device pcap.Interface) string {
    if device.Description != "" {
        parts := strings.Split(device.Description, " ")
        if len(parts) > 0 {
            return parts[0]
        }
        return device.Description
    }
    return "Unknown"
}

func captureOnDevice(device pcap.Interface, localIPs []string, debugMode bool) {
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil { log.Printf("无法打开设备 %s: %v", device.Name, err); return }
	defer handle.Close()
	ipSet := buildIPSet(localIPs)
	// 设置 BPF 过滤器：仅捕获目标为本机IP的 ICMP/ICMPv6
	var v4Filters []string
	var v6Filters []string
	for ip := range ipSet {
		if strings.Contains(ip, ":") { v6Filters = append(v6Filters, fmt.Sprintf("dst host %s", ip)) } else { v4Filters = append(v4Filters, fmt.Sprintf("dst host %s", ip)) }
	}
	var filter string
	if len(v4Filters) > 0 && len(v6Filters) > 0 {
		filter = fmt.Sprintf("(icmp and (%s)) or (icmp6 and (%s))", strings.Join(v4Filters, " or "), strings.Join(v6Filters, " or "))
	} else if len(v4Filters) > 0 {
		filter = fmt.Sprintf("icmp and (%s)", strings.Join(v4Filters, " or "))
	} else if len(v6Filters) > 0 {
		filter = fmt.Sprintf("icmp6 and (%s)", strings.Join(v6Filters, " or "))
	} else {
		filter = "icmp or icmp6"
	}
	if err = handle.SetBPFFilter(filter); err != nil { log.Printf("设置 BPF 过滤器失败 %s: %v", device.Name, err); return }
	ipv4Count := 0; ipv6Count := 0
	for ip := range ipSet { if strings.Contains(ip, ":") { ipv6Count++ } else { ipv4Count++ } }
	fmt.Printf("开始捕获：%s (%s) IPv4[%d] IPv6[%d]\n", device.Name, getDeviceDescription(device), ipv4Count, ipv6Count)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() { processPacketSet(packet, ipSet, debugMode) }
}

func processPacketSet(packet gopacket.Packet, ipSet map[string]struct{}, debugMode bool) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
				srcIP := ip.SrcIP.String(); dstIP := ip.DstIP.String()
				if isLocalIPSet(dstIP, ipSet) {
					if !rateLimiter.CheckSize(srcIP, int(ip.Length)) { if debugMode { log.Printf("🚫 [防御] 阻止来自 %s 的请求（包大小异常/黑名单）", srcIP) } ; return }
					if !rateLimiter.checkRateLimit(srcIP) { if debugMode { log.Printf("🚫 [防御] 阻止来自 %s 的请求（频率限制）", srcIP) } ; return }
					event := Event{ Timestamp: time.Now(), SrcIP: srcIP, DstIP: dstIP, Type: "ICMPv4 Echo Request", Size: int(ip.Length) }
					recordEvent(event, debugMode)
				}
			}
		}
	}
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ip6, _ := ipv6Layer.(*layers.IPv6)
		icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
		if icmpv6Layer != nil {
			icmp6, _ := icmpv6Layer.(*layers.ICMPv6)
			if icmp6.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
				srcIP := ip6.SrcIP.String(); dstIP := ip6.DstIP.String()
				if isLocalIPSet(dstIP, ipSet) {
					if !rateLimiter.CheckSize(srcIP, int(ip6.Length)) { if debugMode { log.Printf("🚫 [防御] 阻止来自 %s 的请求（包大小异常/黑名单）", srcIP) } ; return }
					if !rateLimiter.checkRateLimit(srcIP) { if debugMode { log.Printf("🚫 [防御] 阻止来自 %s 的请求（频率限制/黑名单）", srcIP) } ; return }
					event := Event{ Timestamp: time.Now(), SrcIP: srcIP, DstIP: dstIP, Type: "ICMPv6 Echo Request", Size: int(ip6.Length) }
					recordEvent(event, debugMode)
				}
			}
		}
	}
}

func isLocalIP(ip string, localIPs []string) bool {
	for _, localIP := range localIPs {
		if ip == localIP {
			return true
		}
	}
	return false
}

func buildIPSet(localIPs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(localIPs))
	for _, ip := range localIPs { m[ip] = struct{}{} }
	return m
}

func isLocalIPSet(ip string, ipSet map[string]struct{}) bool {
	_, ok := ipSet[ip]
	return ok
}

func recordEvent(event Event, debugMode bool) {
	mu.Lock()
	defer mu.Unlock()

	// 添加到事件列表
	events = append(events, event)
	
	// 限制事件数量，保留最新的1000条
	if len(events) > 1000 {
		events = events[len(events)-1000:]
	}

	// 更新来源统计
	if stat, exists := sourceStats[event.SrcIP]; exists {
		stat.Count++
		stat.TotalBytes += event.Size
		stat.LastSeen = event.Timestamp
	} else {
		sourceStats[event.SrcIP] = &SourceStat{
			IP:         event.SrcIP,
			Count:      1,
			TotalBytes: event.Size,
			FirstSeen:  event.Timestamp,
			LastSeen:   event.Timestamp,
		}
	}

	if debugMode {
		fmt.Printf("[调试] %s: %s -> %s (%s, %d bytes)\n", 
			event.Timestamp.Format("15:04:05"), event.SrcIP, event.DstIP, event.Type, event.Size)
	}
}

func printSummary(jsonOutput bool) {
	mu.RLock()
	defer mu.RUnlock()

	if len(sourceStats) == 0 {
		if !jsonOutput {
			fmt.Println("暂无记录（未检测到对本机的 Ping）")
		}
		return
	}

	if jsonOutput {
		var summary []SourceStat
		for _, stat := range sourceStats {
			summary = append(summary, *stat)
		}
		sort.Slice(summary, func(i, j int) bool {
			return summary[i].Count > summary[j].Count
		})
		
		output := map[string]interface{}{
			"timestamp": time.Now(),
			"summary":   summary,
		}
		
		jsonData, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("\n=== ICMP 监控汇总 (%s) ===\n", time.Now().Format("2006-01-02 15:04:05"))
		
		var summary []SourceStat
		for _, stat := range sourceStats {
			summary = append(summary, *stat)
		}
		sort.Slice(summary, func(i, j int) bool {
			return summary[i].Count > summary[j].Count
		})

		fmt.Printf("%-15s %8s %12s %19s %19s\n", "来源IP", "次数", "总字节", "首次时间", "最后时间")
		fmt.Println(strings.Repeat("-", 80))
		
		for _, stat := range summary {
			fmt.Printf("%-15s %8d %12d %19s %19s\n",
				stat.IP, stat.Count, stat.TotalBytes,
				stat.FirstSeen.Format("15:04:05"),
				stat.LastSeen.Format("15:04:05"))
		}
		fmt.Println()
	}
}

func startWebServer(addr string) {
	mux := http.NewServeMux()
	// 主页面路由（独立登录页启用后移除遮罩登录）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if authToken != "" && !isAuthorizedBasic(r) {
			setBasicChallenge(w)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		nonce := generateNonce()
		setSecurityHeaders(w, nonce)
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ICMP 监控与防御</title>
    <style>
        :root {
            --bg: #f7f8fb;
            --card: #ffffff;
            --text: #1f2937;
            --muted: #6b7280;
            --primary: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #e5e7eb;
            --table-stripe: #fbfcff;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, 'PingFang SC', 'Microsoft YaHei', sans-serif; margin: 22px; background: var(--bg); color: var(--text); }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg,#334155,#3b82f6); color: white; padding: 20px; border-radius: 14px; margin-bottom: 20px; box-shadow: 0 4px 14px rgba(59,130,246,.2); }
        .header h1 { margin: 0 0 6px; font-weight: 600; }
        .status { display:inline-block; font-size: 13px; padding: 4px 10px; border-radius: 999px; background:#eef3ff; color:#1f2937; }
        .section { background: var(--card); padding: 16px 18px; border-radius: 12px; margin-bottom: 16px; box-shadow: 0 4px 14px rgba(0,0,0,.06); border: 1px solid var(--border); }
        .defense-section { background: #f2fbf5; border-left: 4px solid var(--success); }
        .alert-section { background: #fff7f0; border-left: 4px solid var(--warning); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        thead th { position: sticky; top: 0; z-index: 1; background: #f8fafc; border-bottom: 1px solid var(--border); font-weight: 600; }
        th, td { padding: 9px 12px; text-align: left; border-bottom: 1px solid var(--border); }
        tbody tr:nth-child(odd) { background: var(--table-stripe); }
        tbody tr:hover { background: #eef3ff; transition: background .15s ease; }
        #events-table td:nth-child(2), #events-table td:nth-child(3) { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .2px; }
        #events-table td.col-size { text-align: right; font-variant-numeric: tabular-nums; }
        #summary-table td:nth-child(2), #summary-table td:nth-child(3) { text-align:right; font-variant-numeric: tabular-nums; }
        .status-ok { color: var(--success); font-weight: 600; }
        .status-alert { color: var(--danger); font-weight: 600; }
        .blacklist-ip { background: #ffebee; color: #b91c1c; padding: 2px 6px; border-radius: 6px; }
        .whitelist-ip { background: #e8f5e8; color: #166534; padding: 2px 6px; border-radius: 6px; }
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 16px; }
        .stat-card { background: var(--card); padding: 14px; border-radius: 12px; text-align: center; box-shadow: 0 4px 14px rgba(0,0,0,.06); border: 1px solid var(--border); }
        .stat-number { font-size: 24px; font-weight: 700; color: var(--text); }
        .stat-label { color: var(--muted); margin-top: 6px; font-size: 12px; }
        .switch { position: relative; display: inline-block; width: 46px; height: 24px; vertical-align: middle; margin-left: 8px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #cbd5e1; transition: .2s; border-radius: 24px; }
        .slider:before { position: absolute; content: ''; height: 20px; width: 20px; left: 2px; bottom: 2px; background: #fff; transition: .2s; border-radius: 50%; box-shadow: 0 2px 6px rgba(0,0,0,.15); }
        input:checked + .slider { background: var(--success); }
        input:checked + .slider:before { transform: translateX(22px); }
        #events-table.compact th.col-type, #events-table.compact td.col-type,
        #events-table.compact th.col-size, #events-table.compact td.col-size,
        #events-table.compact th.col-status, #events-table.compact td.col-status { display: none; }
        .table-scroll { max-height: 420px; overflow-y: auto; border: 1px solid var(--border); border-radius: 10px; background: var(--card); }
        .table-scroll::-webkit-scrollbar { width: 8px; }
        .table-scroll::-webkit-scrollbar-thumb { background: #c1c1c1; border-radius: 4px; }
        .table-scroll:hover::-webkit-scrollbar-thumb { background: #999; }
        .status-badge { margin-left: 12px; font-size: 13px; padding: 2px 8px; border-radius: 12px; background: #eef; color: var(--text); }
        .status-error { background: #fee; color: #b91c1c; }
        .segmented { display:inline-flex; border:1px solid var(--border); border-radius:10px; overflow:hidden; background:#fff; vertical-align: middle; }
         .segmented button { padding:6px 10px; font-size:13px; border:0; background:transparent; cursor:pointer; color:var(--text); }
         .segmented button + button { border-left:1px solid var(--border); }
         .segmented button.active { background:#eef3ff; color:#1f2937; font-weight:600; }
         /* 规范化布局 */
         .layout { display:grid; grid-template-columns: 1fr; gap:16px; }
         @media (min-width: 1024px) { .layout { grid-template-columns: 2fr 1fr; } }
         .section h2 { margin:0 0 8px; font-size:16px; }
         .stats { display:grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap:12px; margin:16px 0; }
         .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.06); }
         .stat-number { font-size: 22px; font-weight: 700; }
         .stat-label { font-size: 12px; color: var(--muted); }
         .skip-link { position:absolute; left:-9999px; top:auto; width:1px; height:1px; overflow:hidden; }
         .skip-link:focus { position:static; width:auto; height:auto; padding:8px 12px; background:#fff; border:1px solid var(--border); border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.06); }
         .footer { margin-top: 20px; color: var(--muted); font-size: 12px; text-align: center; }
         .side-toggle { float:right; margin-top:8px; padding:6px 10px; font-size:13px; border:1px solid var(--border); border-radius:8px; background:#fff; cursor:pointer; }
         .segmented button:focus-visible, .side-toggle:focus-visible, a:focus-visible { outline:2px solid var(--primary); outline-offset:2px; }
         @media (prefers-reduced-motion: reduce) { * { transition:none !important; animation:none !important; } }
     </style>
</head>
<body>
    <div class="container">
        <header class="header" role="banner">
            <a class="skip-link" href="#main-content">跳到主要内容</a>
            <h1>ICMP 监控与防御</h1>
            <div id="api-status" class="status" aria-live="polite">连接中…</div>
            <button id="toggle-aside" class="side-toggle" aria-controls="side-col" aria-expanded="true">折叠侧栏</button>
        </header>
        <div class="stats">
            <div class="stat-card"><div class="stat-number" id="total-events">0</div><div class="stat-label">总事件数</div></div>
            <div class="stat-card"><div class="stat-number" id="unique-sources">0</div><div class="stat-label">唯一来源</div></div>
            <div class="stat-card"><div class="stat-number" id="blacklisted-count">0</div><div class="stat-label">黑名单IP</div></div>
            <div class="stat-card"><div class="stat-number" id="blocked-total">0</div><div class="stat-label">被阻止总数</div></div>
            <div class="stat-card"><div class="stat-number" id="defense-status">🟢</div><div class="stat-label">防御状态</div></div>
        </div>
        <main class="layout" role="main" id="main-content">
          <section class="main-col">
            <section class="section" aria-labelledby="events-title">
              <h2 id="events-title">📊 最近事件 <span id="limit-label" class="status-badge">数量：全部</span> <span style="font-weight:normal; font-size:14px; margin-left:12px;">简洁模式</span><label class="switch"><input type="checkbox" id="toggle-compact"><span class="slider"></span></label></h2>
              <div style="margin:8px 0 4px;">
                <div class="segmented" id="limit-seg">
                  <button id="limit-100">100</button>
                  <button id="limit-500">500</button>
                  <button id="limit-all">全部</button>
                </div>
              </div>
              <div class="table-scroll" id="events-scroll">
                <table id="events-table" aria-describedby="events-title">
                  <caption class="visually-hidden">最近事件列表</caption>
                  <thead><tr><th>时间</th><th>来源IP</th><th>目标IP</th><th class="col-type">类型</th><th class="col-size">大小</th><th class="col-status">状态</th></tr></thead>
                  <tbody id="events-body"><tr><td colspan="6">暂无数据</td></tr></tbody>
                </table>
              </div>
            </section>
            <section class="section" aria-labelledby="summary-title">
              <h2 id="summary-title">📈 来源主机汇总</h2>
              <table id="summary-table" aria-describedby="summary-title">
                <caption class="visually-hidden">来源主机汇总表</caption>
                <thead><tr><th>来源IP</th><th>请求次数</th><th>总字节数</th><th>首次时间</th><th>最后时间</th><th>状态</th></tr></thead>
                <tbody id="summary-body"><tr><td colspan="6">暂无数据</td></tr></tbody>
              </table>
            </section>
          </section>
          <aside class="side-col" id="side-col" aria-label="防御与黑名单">
            <section class="section defense-section">
              <h2>🛡️ 防御配置</h2>
              <div id="defense-config">
                <div id="defense-current" style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-bottom:8px;">
                  <div>每秒限制：<strong id="rate_limit_second_val">-</strong></div>
                  <div>每分钟限制：<strong id="rate_limit_minute_val">-</strong></div>
                  <div>每秒突发：<strong id="burst_per_second_val">-</strong></div>
                  <div>告警阈值：<strong id="alert_threshold_val">-</strong></div>
                  <div>黑名单时长：<strong id="blacklist_duration_val">-</strong></div>
                  <div>最大包大小：<strong id="max_packet_size_val">-</strong></div>
                  <div>启用防火墙：<strong id="enable_firewall_val">-</strong></div>
                  <div>防火墙状态：<strong id="firewall_status_val">-</strong></div>
                  <div style="grid-column:1/-1;">白名单：<span id="whitelist_vals" style="color:var(--muted)">暂无</span></div>
                </div>
                <div id="defense-form">
                  <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;">
                    <label>每秒限制<input type="number" id="inp-rate-second" min="1" style="width:100%"></label>
                    <label>每分钟限制<input type="number" id="inp-rate-minute" min="1" style="width:100%"></label>
                    <label>每秒突发<input type="number" id="inp-burst-second" min="1" style="width:100%"></label>
                    <label>告警阈值<input type="number" id="inp-alert-threshold" min="1" style="width:100%"></label>
                    <label>黑名单秒<input type="number" id="inp-blacklist-seconds" min="1" style="width:100%"></label>
                    <label>最大包大小<input type="number" id="inp-max-packet-size" min="0" style="width:100%"></label>
                    <label style="grid-column:1/-1;">白名单（逗号分隔）
                      <input type="text" id="inp-whitelist" placeholder="示例：127.0.0.1,192.168.1.1" style="width:100%">
                    </label>
                    <label style="grid-column:1/-1;"><input type="checkbox" id="inp-sound"> 启用声音告警</label>
                    <label style="grid-column:1/-1;"><input type="checkbox" id="inp-firewall"> 启用系统防火墙拦截</label>
                  </div>
                  <div style="margin-top:8px;display:flex;gap:8px;">
                    <button id="btn-update-config" class="side-toggle">更新配置</button>
                    <button id="btn-clear-blacklist" class="side-toggle">清空黑名单</button>
                    <span id="defense-action-status" style="margin-left:8px;color:var(--muted)"></span>
                  </div>
                </div>
              </div>
            </section>
            <section class="section alert-section">
              <h2>⚠️ 黑名单 IP</h2>
              <div id="blacklist-info">暂无被阻止的IP</div>
            </section>
            <section class="section alert-section" id="blocked-section">
              <h2>🚫 被阻止统计 <label style="font-weight:normal; font-size:14px;"><input type="checkbox" id="toggle-blocked" checked> 显示/隐藏</label></h2>
              <div id="blocked-info">暂无阻止记录</div>
            </section>
          </aside>
        </main>
    </div>
    <script nonce="%[1]s">
    var evLimit = (localStorage.getItem('evLimit') || 'all');
    function applyLimitLabel() { var lbl = document.getElementById('limit-label'); if (!lbl) return; lbl.textContent = '数量：' + (evLimit === 'all' ? '全部' : evLimit); }
    function td(v) { return '<td>' + v + '</td>'; }
    function formatTimeLocal(s) {
      var d = new Date(s);
      if (isNaN(d.getTime())) return s || '';
      return d.toLocaleTimeString(undefined, { hour12: false });
    }
    async function update() {
      try {
        const url = '/api/events?top=20' + (evLimit === 'all' ? '&limit=all' : ('&limit=' + evLimit));
        const resp = await fetch(url, { cache: 'no-store' });
        if (resp.status === 401) { document.getElementById('api-status').textContent = '未授权'; return; }
        const data = await resp.json();
        const events = data.events || [];
        const summary = data.summary || [];
        document.getElementById('total-events').textContent = events.length;
        document.getElementById('unique-sources').textContent = summary.length;
        var tbody = document.getElementById('events-body');
        tbody.innerHTML = '';
        for (var i = 0; i < events.length; i++) {
          var e = events[i];
          var t = formatTimeLocal(e.timestamp);
          var row = td(t) + td(e.src_ip) + td(e.dst_ip)
                  + '<td class="col-type">' + (e.type || '') + '</td>'
                  + '<td class="col-size">' + (e.size || '') + '</td>'
                  + '<td class="col-status">通过</td>';
          var tr = document.createElement('tr');
          tr.innerHTML = row;
          tbody.appendChild(tr);
        }
        var sbody = document.getElementById('summary-body');
        sbody.innerHTML = '';
        for (var j = 0; j < summary.length; j++) {
          var s = summary[j];
          var fs = formatTimeLocal(s.first_seen);
          var ls = formatTimeLocal(s.last_seen);
          var row2 = td(s.ip) + td(s.count) + td(s.total_bytes) + td(fs) + td(ls) + td('活跃');
          var tr2 = document.createElement('tr');
          tr2.innerHTML = row2;
          sbody.appendChild(tr2);
        }
        document.getElementById('api-status').textContent = '已连接';
      } catch (err) {
        document.getElementById('api-status').textContent = '连接失败';
      }
    }
    async function updateDefense() {
      try {
        const resp = await fetch('/api/defense', { cache: 'no-store' });
        if (resp.status === 401) { return; }
        const d = await resp.json();

        // 顶部统计卡片
        document.getElementById('blacklisted-count').textContent = d.blacklist_count || 0;
        document.getElementById('blocked-total').textContent = d.blocked_total || 0;

        // 当前配置值展示
        var wl = Array.isArray(d.whitelist) ? d.whitelist : [];
        var wlChips = wl.length ? wl.map(function(ip){ return '<span class="whitelist-ip">'+ip+'</span>'; }).join(' ') : '<span style="color:var(--muted)">暂无</span>';
        var wln = document.getElementById('whitelist_vals'); if (wln) wln.innerHTML = wlChips;
        var el;
        el=document.getElementById('rate_limit_second_val'); if(el) el.textContent = (d.rate_limit_second ?? '-');
        el=document.getElementById('rate_limit_minute_val'); if(el) el.textContent = (d.rate_limit_minute ?? '-');
        el=document.getElementById('burst_per_second_val'); if(el) el.textContent = (d.burst_per_second ?? '-');
        el=document.getElementById('alert_threshold_val'); if(el) el.textContent = (d.alert_threshold ?? '-');
        el=document.getElementById('blacklist_duration_val'); if(el) el.textContent = (d.blacklist_duration ?? '-');
        el=document.getElementById('max_packet_size_val'); if(el) el.textContent = (d.max_packet_size ?? '-');
        el=document.getElementById('enable_firewall_val'); if(el) el.textContent = (d.enable_firewall ? '是' : '否');
        el=document.getElementById('firewall_status_val'); if(el) el.textContent = (d.firewall_status ?? '-');
        var fwChk = document.getElementById('inp-firewall'); if (fwChk) fwChk.checked = !!d.enable_firewall;
        el=document.getElementById('enable_firewall_val'); if(el) el.textContent = (d.enable_firewall ? '是' : '否');

        // 表单值同步
        var i;
        i=document.getElementById('inp-rate-second'); if(i) i.value = (typeof d.rate_limit_second==='number' ? d.rate_limit_second : '');
        i=document.getElementById('inp-rate-minute'); if(i) i.value = (typeof d.rate_limit_minute==='number' ? d.rate_limit_minute : '');
        i=document.getElementById('inp-alert-threshold'); if(i) i.value = (typeof d.alert_threshold==='number' ? d.alert_threshold : '');
        i=document.getElementById('inp-blacklist-seconds'); if(i) { var sec = parseDurationSeconds(d.blacklist_duration || ''); i.value = sec || ''; }
        i=document.getElementById('inp-max-packet-size'); if(i) i.value = (typeof d.max_packet_size==='number' ? d.max_packet_size : '');
        i=document.getElementById('inp-whitelist'); if(i) i.value = wl.join(',');
        var snd = document.getElementById('inp-sound'); if (snd && typeof d.enable_sound !== 'undefined') snd.checked = !!d.enable_sound;
        var fw = document.getElementById('inp-firewall'); if (fw && typeof d.enable_firewall !== 'undefined') fw.checked = !!d.enable_firewall;
        var bs = document.getElementById('inp-burst-second'); if (bs && typeof d.burst_per_second !== 'undefined') bs.value = d.burst_per_second;

        // 黑名单 IP 标签
        var blEntries = Array.isArray(d.blacklist_entries) ? d.blacklist_entries : [];
        var blHtml;
        if (blEntries.length) {
          blHtml = blEntries.map(function(e){
            var ip = e.ip || '';
            var reason = e.reason || '未知';
            var rem = (typeof e.remaining_seconds !== 'undefined') ? e.remaining_seconds : 0;
            return '<span class="blacklist-ip">'+ ip +' <span style="color:var(--muted)">(' + reason + ', ' + rem + 's)</span></span>';
          }).join(' ');
        } else {
          var bl = Array.isArray(d.blacklisted_ips) ? d.blacklisted_ips : [];
          blHtml = bl.length ? bl.map(function(ip){ return '<span class="blacklist-ip">'+ip+'</span>'; }).join(' ') : '暂无被阻止的IP';
        }
        var blNode = document.getElementById('blacklist-info');
        if (blNode) { blNode.innerHTML = blHtml; }

        // 被阻止统计列表
        var blocked = d.blocked_counts || {};
        var keys = Object.keys(blocked);
        var blockedHtml = keys.length
          ? '<ul style="margin:0;padding-left:18px;">' + keys.map(function(ip){
              return '<li>'+ ip +'：<strong>'+ blocked[ip] +'</strong> 次</li>';
            }).join('') + '</ul>'
          : '暂无阻止记录';
        var blockedNode = document.getElementById('blocked-info');
        if (blockedNode) { blockedNode.innerHTML = blockedHtml; }
      } catch (err) {}
    }
    function parseDurationSeconds(str) {
      if (!str || typeof str !== 'string') return 0;
      var sec = 0; var m;
      m = str.match(/(\\d+)h/); if (m) sec += parseInt(m[1]) * 3600;
      m = str.match(/(\\d+)m/); if (m) sec += parseInt(m[1]) * 60;
      m = str.match(/(\\d+)s/); if (m) sec += parseInt(m[1]);
      return sec;
    }
    function bindDefenseControls() {
      var btnUpdate = document.getElementById('btn-update-config');
      var btnClear = document.getElementById('btn-clear-blacklist');
      var status = document.getElementById('defense-action-status');
      function setStatus(text) { if (status) { status.textContent = text; } }
      if (btnUpdate) {
        btnUpdate.addEventListener('click', async function(){
          var payload = {};
          var v;
          v = document.getElementById('inp-rate-second'); if (v && v.value) payload.rate_limit_per_second = parseInt(v.value);
          v = document.getElementById('inp-rate-minute'); if (v && v.value) payload.rate_limit_per_minute = parseInt(v.value);
          v = document.getElementById('inp-burst-second'); if (v && v.value) payload.burst_per_second = parseInt(v.value);
          v = document.getElementById('inp-alert-threshold'); if (v && v.value) payload.alert_threshold = parseInt(v.value);
          v = document.getElementById('inp-blacklist-seconds'); if (v && v.value) payload.blacklist_duration_seconds = parseInt(v.value);
          v = document.getElementById('inp-max-packet-size'); if (v && v.value) payload.max_packet_size = parseInt(v.value);
          v = document.getElementById('inp-whitelist'); if (v && v.value) payload.whitelist = v.value.split(',').map(function(s){ return s.trim(); }).filter(function(s){ return s.length>0; });
          var snd = document.getElementById('inp-sound'); if (snd) payload.enable_sound = !!snd.checked;
          var fw = document.getElementById('inp-firewall'); if (fw) payload.enable_firewall = !!fw.checked;
          try {
            setStatus('更新中…');
            var resp = await fetch('/api/defense/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
            if (resp.status === 200) { setStatus('已更新'); updateDefense(); }
            else if (resp.status === 401) { setStatus('未授权'); }
            else { setStatus('更新失败'); }
          } catch (e) { setStatus('网络错误'); }
        });
      }
      if (btnClear) {
        btnClear.addEventListener('click', async function(){
          try {
            setStatus('清空中…');
            var resp = await fetch('/api/defense/clear', { method: 'POST' });
            if (resp.status === 200) { setStatus('已清空'); updateDefense(); }
            else if (resp.status === 401) { setStatus('未授权'); }
            else { setStatus('操作失败'); }
          } catch (e) { setStatus('网络错误'); }
        });
      }
    }
    document.addEventListener('DOMContentLoaded', function () {
      var compactToggle = document.getElementById('toggle-compact');
      var table = document.getElementById('events-table');
      if (compactToggle) { compactToggle.addEventListener('change', function () { if (compactToggle.checked) { table.classList.add('compact'); } else { table.classList.remove('compact'); } }); }
      var blockedToggle = document.getElementById('toggle-blocked');
      var blockedSec = document.getElementById('blocked-section');
      if (blockedToggle && blockedSec) { blockedToggle.addEventListener('change', function () { blockedSec.style.display = blockedToggle.checked ? 'block' : 'none'; }); }
      // 侧栏折叠
      var asideToggle = document.getElementById('toggle-aside');
      var aside = document.getElementById('side-col');
      if (asideToggle && aside) {
        asideToggle.addEventListener('click', function(){
          var visible = aside.style.display !== 'none';
          aside.style.display = visible ? 'none' : 'block';
          asideToggle.setAttribute('aria-expanded', (!visible).toString());
          asideToggle.textContent = visible ? '展开侧栏' : '折叠侧栏';
        });
      }
      // 事件数量切换
      var btn100 = document.getElementById('limit-100');
      var btn500 = document.getElementById('limit-500');
      var btnAll = document.getElementById('limit-all');
      function setActive() {
        [btn100, btn500, btnAll].forEach(function(b){ if(!b) return; b.classList.remove('active'); });
        if (evLimit === '100' && btn100) btn100.classList.add('active');
        else if (evLimit === '500' && btn500) btn500.classList.add('active');
        else if (btnAll) btnAll.classList.add('active');
      }
      if (btn100) btn100.addEventListener('click', function(){ evLimit='100'; localStorage.setItem('evLimit','100'); applyLimitLabel(); setActive(); update(); });
      if (btn500) btn500.addEventListener('click', function(){ evLimit='500'; localStorage.setItem('evLimit','500'); applyLimitLabel(); setActive(); update(); });
      if (btnAll) btnAll.addEventListener('click', function(){ evLimit='all'; localStorage.setItem('evLimit','all'); applyLimitLabel(); setActive(); update(); });
      applyLimitLabel(); setActive(); bindDefenseControls();
      update(); updateDefense();
      setInterval(update, 1500);
      setInterval(updateDefense, 5000);
    });
    </script>
    <footer class="footer" role="contentinfo">ICMP 监控与防御 · Web UI</footer>
</body>
</html>`, nonce)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write([]byte(html))
    })

    mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        setBasicChallenge(w)
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusUnauthorized)
        w.Write([]byte("请使用浏览器的 HTTP 基本认证访问。"))
    })

    mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
        // 认证（Basic）
        if authToken != "" && !isAuthorizedBasic(r) {
            setBasicChallenge(w)
            setJSONHeaders(w)
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]interface{}{
                "error":   "unauthorized",
                "code":    http.StatusUnauthorized,
                "message": "missing or invalid credentials",
            })
            return
        }
        // 读取limit/top参数（limit 默认无限制；支持 limit=all 或 <=0 表示全部）
        q := r.URL.Query()
        limit := -1
        if s := q.Get("limit"); s != "" {
            if strings.EqualFold(s, "all") {
                limit = -1
            } else if v, err := strconv.Atoi(s); err == nil {
                if v > 0 { limit = v } else { limit = -1 }
            }
        }
        top := 20
        if s := q.Get("top"); s != "" {
            if v, err := strconv.Atoi(s); err == nil && v > 0 {
                top = v
            }
        }

        mu.RLock()
        total := len(events)
        tail := total
        if limit > 0 && limit < total { tail = limit }
        eventsCopy := make([]Event, tail)
        if tail > 0 {
            copy(eventsCopy, events[total-tail:])
        }
        var summary []SourceStat
        for _, stat := range sourceStats {
            summary = append(summary, *stat)
        }
        mu.RUnlock()

        sort.Slice(summary, func(i, j int) bool {
            return summary[i].Count > summary[j].Count
        })
        if len(summary) > top {
            summary = summary[:top]
        }

        response := map[string]interface{}{
            "events":  eventsCopy,
            "summary": summary,
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })

    mux.HandleFunc("/api/defense", func(w http.ResponseWriter, r *http.Request) {
        if authToken != "" && !isAuthorizedBasic(r) {
            setBasicChallenge(w)
            setJSONHeaders(w)
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]interface{}{
                "error":   "unauthorized",
                "code":    http.StatusUnauthorized,
                "message": "missing or invalid credentials",
            })
            return
        }
        stats := rateLimiter.getDefenseStats()
        setJSONHeaders(w)
        json.NewEncoder(w).Encode(stats)
    })

    // 清空黑名单（POST）
    mux.HandleFunc("/api/defense/clear", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            setJSONHeaders(w)
            w.WriteHeader(http.StatusMethodNotAllowed)
            _ = json.NewEncoder(w).Encode(map[string]string{"error":"method_not_allowed"})
            return
        }
        if authToken != "" && !isAuthorizedBasic(r) {
            setBasicChallenge(w)
            setJSONHeaders(w)
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]interface{}{
                "error":   "unauthorized",
                "code":    http.StatusUnauthorized,
                "message": "missing or invalid credentials",
            })
            return
        }
        rateLimiter.ClearBlacklist()
        setJSONHeaders(w)
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
    })

    // 更新防御配置（POST）
    mux.HandleFunc("/api/defense/config", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            setJSONHeaders(w)
            w.WriteHeader(http.StatusMethodNotAllowed)
            _ = json.NewEncoder(w).Encode(map[string]string{"error":"method_not_allowed"})
            return
        }
        if authToken != "" && !isAuthorizedBasic(r) {
            setBasicChallenge(w)
            setJSONHeaders(w)
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(map[string]interface{}{
                "error":   "unauthorized",
                "code":    http.StatusUnauthorized,
                "message": "missing or invalid credentials",
            })
            return
        }
        var upd DefenseConfigUpdate
        if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
            setJSONHeaders(w)
            w.WriteHeader(http.StatusBadRequest)
            _ = json.NewEncoder(w).Encode(map[string]string{"error":"bad_request","message":"invalid json"})
            return
        }
        rateLimiter.UpdateConfig(upd)
        setJSONHeaders(w)
        // 返回最新防御状态，便于前端刷新
        _ = json.NewEncoder(w).Encode(rateLimiter.getDefenseStats())
    })

    // 移除基于 Cookie 的 /api/login 与 /api/logout，保留但不启用
    mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
        setBasicChallenge(w)
        setJSONHeaders(w)
        w.WriteHeader(http.StatusUnauthorized)
        _ = json.NewEncoder(w).Encode(map[string]string{"error":"basic_auth_required"})
    })
    mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
        setBasicChallenge(w)
        setJSONHeaders(w)
        w.WriteHeader(http.StatusUnauthorized)
        _ = json.NewEncoder(w).Encode(map[string]string{"error":"basic_auth_required"})
    })

    if tlsCertPath != "" && tlsKeyPath != "" {
        log.Fatal(http.ListenAndServeTLS(addr, tlsCertPath, tlsKeyPath, mux))
    } else {
        log.Fatal(http.ListenAndServe(addr, mux))
    }
}

func isAuthorizedBasic(r *http.Request) bool {
    if authToken == "" {
        return true
    }
    ip := getRemoteIP(r)
    
    // 若该IP已在黑名单，直接拒绝
    if rateLimiter != nil && rateLimiter.isBlacklisted(ip) {
        return false
    }
    
    auth := r.Header.Get("Authorization")
    if strings.HasPrefix(auth, "Basic ") {
        enc := strings.TrimSpace(strings.TrimPrefix(auth, "Basic "))
        b, err := base64.StdEncoding.DecodeString(enc)
        if err == nil {
            parts := strings.SplitN(string(b), ":", 2)
            if len(parts) == 2 {
                // 用户名不匹配直接判定失败，不泄露真实用户名
                if authUser != "" && parts[0] != authUser {
                    // 记录失败
                    registerAuthFail(ip)
                    return false
                }
                if parts[1] == authToken {
                    // 成功则可选择重置失败计数（提高用户体验）
                    resetAuthFail(ip)
                    return true
                }
            }
        }
    }
    // 记录失败并根据策略可能封禁
    registerAuthFail(ip)
    return false
}

// 记录认证失败并按窗口进行封禁
func registerAuthFail(ip string) {
    now := time.Now()
    // 取窗口起点
    if val, ok := authLastWindow.Get(ip); ok {
        if start, ok := val.(time.Time); ok {
            if now.Sub(start) > 1*time.Minute {
                // 窗口过期，重置
                authLastWindow.Set(ip, now)
                authFailCounts.Set(ip, 1)
            } else {
                // 累加失败
                if cval, ok := authFailCounts.Get(ip); ok {
                    if c, ok := cval.(int); ok { authFailCounts.Set(ip, c+1) } else { authFailCounts.Set(ip, 1) }
                } else { authFailCounts.Set(ip, 1) }
            }
        } else {
            authLastWindow.Set(ip, now)
            authFailCounts.Set(ip, 1)
        }
    } else {
        authLastWindow.Set(ip, now)
        authFailCounts.Set(ip, 1)
    }
    
    // 阈值策略：1分钟内>=5次失败 或 10分钟内>=20次失败 => 黑名单10分钟
    count := 0
    if cval, ok := authFailCounts.Get(ip); ok { if c, ok := cval.(int); ok { count = c } }
    if count >= 5 {
        if rateLimiter != nil {
            rateLimiter.blockedReasons.Set(ip, "auth_bruteforce")
            rateLimiter.addToBlacklist(ip)
            rateLimiter.incrementBlocked(ip)
        }
        // 重置计数，避免无限增长
        authFailCounts.Delete(ip)
        authLastWindow.Delete(ip)
    }
}

func resetAuthFail(ip string) {
    authFailCounts.Delete(ip)
    authLastWindow.Delete(ip)
}

func setBasicChallenge(w http.ResponseWriter) {
    w.Header().Set("WWW-Authenticate", `Basic realm="ICMP Monitor"`)
}

func generateNonce() string {
    b := make([]byte, 16)
    _, _ = rand.Read(b)
    return base64.RawStdEncoding.EncodeToString(b)
}

func setSecurityHeaders(w http.ResponseWriter, nonce string) {
    csp := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'", nonce)
    w.Header().Set("Content-Security-Policy", csp)
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("Referrer-Policy", "no-referrer")
    w.Header().Set("Cache-Control", "no-store")
}

func setJSONHeaders(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-store")
}

func getAuthCookieValue(r *http.Request) string {
    c, err := r.Cookie("auth_token")
    if err != nil {
        return ""
    }
    return c.Value
}

func setAuthCookie(w http.ResponseWriter, token string) {
    c := &http.Cookie{
        Name:     "auth_token",
        Value:    token,
        Path:     "/",
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
        Expires:  time.Now().Add(24 * time.Hour),
    }
    w.Header().Add("Set-Cookie", c.String())
}

func clearAuthCookie(w http.ResponseWriter) {
    c := &http.Cookie{
        Name:     "auth_token",
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
        Expires:  time.Unix(0, 0),
        MaxAge:   -1,
    }
    w.Header().Add("Set-Cookie", c.String())
}

func isLoopbackDevice(device pcap.Interface) bool {
    name := strings.ToLower(device.Name)
    desc := strings.ToLower(device.Description)
    if name == "lo" { return true }
    if strings.Contains(name, "loopback") { return true }
    if strings.Contains(desc, "loopback") { return true }
    return false
}