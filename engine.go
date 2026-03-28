package main

import (
	"log"
	"regexp"
	"strings"
)

// ── Pattern definitions ───────────────────────────────────────────────────────

type Pattern struct {
	ID       string
	NameZh   string
	NameEn   string
	Severity string
	Category string
	DescZh   string
	DescEn   string
	Re       *regexp.Regexp
}

var patterns []*Pattern

func init() {
	// Order matters: more specific patterns must come before general ones.
	// ID card and bank card are placed before phone to prevent a long digit
	// sequence (e.g. an 18-digit ID) from being partially matched as a phone number.
	defs := []struct {
		id, nameZh, nameEn, severity, category, descZh, descEn, reStr string
	}{
		{
			"P002", "身份证号码", "Chinese ID Card", "high", "identity",
			"检测到中国居民身份证号码，属于高度敏感的个人信息。",
			"Chinese ID card number detected, highly sensitive personal information.",
			`[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`,
		},
		{
			"P003", "银行卡号", "Bank Card Number", "high", "financial",
			"检测到银行卡号，属于高度敏感的金融信息，存在资金安全风险。",
			"Bank card number detected, highly sensitive financial information with monetary risk.",
			`\b(?:62\d{14,17}|4\d{15}|5[1-5]\d{14})\b`,
		},
		{
			"P006", "JWT Token", "JWT Token", "medium", "credential",
			"检测到 JWT Token，可能导致身份验证凭据泄露。",
			"JWT Token detected, may lead to authentication credential exposure.",
			`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
		},
		{
			"P007", "密钥/密码明文", "Credential / Secret", "high", "credential",
			"检测到明文密码或密钥，存在严重的凭据泄露风险。",
			"Plaintext password or secret key detected, serious credential exposure risk.",
			`(?i)(?:password|passwd|pwd|secret|api_?key|access_?token|private_?key|auth_?token)\s*[=:]\s*["']?[^\s"',;]{6,}["']?`,
		},
		{
			"P001", "手机号码", "Mobile Phone Number", "high", "identity",
			"检测到中国大陆手机号码，可能涉及用户隐私泄露。",
			"Chinese mainland mobile phone number detected, may involve user privacy exposure.",
			`(?:\+86|0086)?1[3-9]\d{9}`,
		},
		{
			"P004", "电子邮箱", "Email Address", "medium", "contact",
			"检测到电子邮箱地址，可能涉及用户联系信息泄露。",
			"Email address detected, may involve exposure of user contact information.",
			`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		},
		{
			"P005", "IPv4 地址", "IPv4 Address", "low", "network",
			"检测到 IPv4 地址，可能泄露内网拓扑或服务器信息。",
			"IPv4 address detected, may reveal internal network topology or server information.",
			`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`,
		},
	}

	for _, d := range defs {
		re := regexp.MustCompile(d.reStr)
		patterns = append(patterns, &Pattern{
			ID:       d.id,
			NameZh:   d.nameZh,
			NameEn:   d.nameEn,
			Severity: d.severity,
			Category: d.category,
			DescZh:   d.descZh,
			DescEn:   d.descEn,
			Re:       re,
		})
	}
	log.Printf("Loaded %d DLP patterns", len(patterns))
}

// ── Masking ───────────────────────────────────────────────────────────────────

func maskValue(patternID, value string) string {
	switch patternID {
	case "P001": // Phone: show first 3, mask 4, show last 4
		if len(value) >= 11 {
			// strip prefix +86 or 0086
			digits := value
			if strings.HasPrefix(digits, "+86") {
				digits = digits[3:]
			} else if strings.HasPrefix(digits, "0086") {
				digits = digits[4:]
			}
			if len(digits) >= 11 {
				return digits[:3] + "****" + digits[len(digits)-4:]
			}
		}
		return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
	case "P002": // ID: show first 6, mask 8, show last 4
		if len(value) >= 18 {
			return value[:6] + "********" + value[len(value)-4:]
		}
		return strings.Repeat("*", len(value))
	case "P003": // Bank card: mask all but last 4
		if len(value) >= 4 {
			return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
		}
		return strings.Repeat("*", len(value))
	case "P004": // Email: show first char + domain
		atIdx := strings.Index(value, "@")
		if atIdx > 0 {
			return value[:1] + "***" + value[atIdx:]
		}
		return value[:1] + "***"
	case "P005": // IP: show first 2 octets
		parts := strings.Split(value, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".*.*"
		}
		return value
	case "P006": // JWT: show header, mask rest
		dotIdx := strings.Index(value, ".")
		if dotIdx > 0 {
			return value[:dotIdx] + ".***"
		}
		return value[:7] + ".***"
	case "P007": // Credential: show key, mask value
		for _, sep := range []string{"=", ":"} {
			idx := strings.Index(value, sep)
			if idx > 0 {
				key := value[:idx+1]
				return key + "***"
			}
		}
		return "***"
	}
	return strings.Repeat("*", len(value))
}

// ── Data types ────────────────────────────────────────────────────────────────

type Finding struct {
	PatternID   string   `json:"patternId"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Count       int      `json:"count"`
	Samples     []string `json:"samples"`
}

type ScanResult struct {
	Success    bool      `json:"success"`
	Findings   []Finding `json:"findings"`
	TotalCount int       `json:"totalCount"`
	RiskLevel  string    `json:"riskLevel"`
	Error      string    `json:"error,omitempty"`
}

type Replacement struct {
	PatternID string `json:"patternId"`
	Name      string `json:"name"`
	Count     int    `json:"count"`
}

type DesensitizeResult struct {
	Success      bool          `json:"success"`
	Desensitized string        `json:"desensitized"`
	Replacements []Replacement `json:"replacements"`
	TotalCount   int           `json:"totalCount"`
	Error        string        `json:"error,omitempty"`
}

type Request struct {
	Text   string `json:"text"`
	Locale string `json:"locale"`
}

// ── Risk level calculation ────────────────────────────────────────────────────

func calcRiskLevel(findings []Finding) string {
	if len(findings) == 0 {
		return "none"
	}
	for _, f := range findings {
		if f.Severity == "high" {
			return "high"
		}
	}
	for _, f := range findings {
		if f.Severity == "medium" {
			return "medium"
		}
	}
	return "low"
}

// ── Span overlap detection ────────────────────────────────────────────────────

type span struct{ start, end int }

func overlaps(s span, used []span) bool {
	for _, u := range used {
		if s.start < u.end && s.end > u.start {
			return true
		}
	}
	return false
}

// ── Core scan logic ───────────────────────────────────────────────────────────

func scanText(text, locale string) ScanResult {
	var findings []Finding
	total := 0
	// Track byte ranges already claimed by a higher-priority pattern.
	var usedSpans []span

	for _, p := range patterns {
		allIdx := p.Re.FindAllStringIndex(text, -1)
		if len(allIdx) == 0 {
			continue
		}

		name := p.NameEn
		desc := p.DescEn
		if locale == "zh" {
			name = p.NameZh
			desc = p.DescZh
		}

		// Only keep matches that do not overlap with already-matched regions.
		seen := make(map[string]bool)
		var samples []string
		count := 0
		for _, idx := range allIdx {
			s := span{idx[0], idx[1]}
			if overlaps(s, usedSpans) {
				continue
			}
			usedSpans = append(usedSpans, s)
			count++
			m := text[idx[0]:idx[1]]
			if !seen[m] && len(samples) < 3 {
				seen[m] = true
				samples = append(samples, maskValue(p.ID, m))
			}
		}
		if count == 0 {
			continue
		}

		total += count
		findings = append(findings, Finding{
			PatternID:   p.ID,
			Name:        name,
			Severity:    p.Severity,
			Category:    p.Category,
			Description: desc,
			Count:       count,
			Samples:     samples,
		})
	}

	if findings == nil {
		findings = []Finding{}
	}

	return ScanResult{
		Success:    true,
		Findings:   findings,
		TotalCount: total,
		RiskLevel:  calcRiskLevel(findings),
	}
}

// ── Core desensitize logic ────────────────────────────────────────────────────

func desensitizeText(text, locale string) DesensitizeResult {
	result := text
	var replacements []Replacement
	total := 0

	for _, p := range patterns {
		matches := p.Re.FindAllString(result, -1)
		if len(matches) == 0 {
			continue
		}

		name := p.NameEn
		if locale == "zh" {
			name = p.NameZh
		}

		count := 0
		result = p.Re.ReplaceAllStringFunc(result, func(m string) string {
			count++
			return maskValue(p.ID, m)
		})

		total += count
		replacements = append(replacements, Replacement{
			PatternID: p.ID,
			Name:      name,
			Count:     count,
		})
	}

	if replacements == nil {
		replacements = []Replacement{}
	}

	return DesensitizeResult{
		Success:      true,
		Desensitized: result,
		Replacements: replacements,
		TotalCount:   total,
	}
}
