package dnscontrol

// These are discovery templates, not a declaration of service availability.
// Operator documentation was read on 2026-09-13; no public endpoints were probed.
func communityDNSProviders() []Provider {
	return []Provider{
		{ID: "malw", Name: "dns.malw.link", Description: "Сторонний Smart DNS и фильтрация. Заявления оператора не являются локальной проверкой.", DoH: "https://dns.malw.link/dns-query", DoT: "dns.malw.link:853", Filters: []string{"Smart DNS", "фильтрация"}, Configured: true, EncryptedOnly: true, DocumentationURL: "https://info.dns.malw.link/", DocumentationCheckedAt: "2026-09-13", ServiceHints: []string{"chatgpt", "gemini", "claude"}},
		{ID: "comss", Name: "Comss.one DNS", Description: "Сторонний сервисный DNS с фильтрацией рекламы и угроз.", DoH: "https://dns.comss.one/dns-query", DoT: "dns.comss.one:853", Filters: []string{"Smart DNS", "реклама", "угрозы"}, Configured: true, EncryptedOnly: true, DocumentationURL: "https://www.comss.ru/page.php?id=7315", DocumentationCheckedAt: "2026-09-13", ServiceHints: []string{"chatgpt", "gemini", "claude"}},
		{ID: "geohide", Name: "GeoHide DNS", Description: "Исследовательский шаблон. Не подставляет неподтверждённые адреса шлюзов.", RequiresConfiguration: true, ConfigurationHint: "Проверить официальный endpoint и условия оператора. Списки hosts — не DNS endpoint.", DocumentationURL: "https://github.com/Internet-Helper/GeoHideDNS"},
		{ID: "controld-redirect", Name: "Control D Redirect", Description: "Отдельный аккаунтный Smart DNS, не бесплатный Control D Unfiltered.", RequiresConfiguration: true, ConfigurationHint: "Аккаунт, разрешённый API и согласование исходящего адреса ещё требуют интеграции.", DocumentationURL: "https://docs.controld.com/docs/custom-rules"},
	}
}
func withProviderMetadata(p Provider) Provider {
	p.Kind = "resolver"
	p.Trust = "operator"
	switch p.ID {
	case "system":
		p.Kind = "system"
		p.Trust = "local"
	case "quad9", "quad9-secure-ecs", "adguard", "adguard-family", "nextdns":
		p.Kind = "filtering-resolver"
	case "controld-uncensored", "uncensoreddns":
		p.Kind = "uncensored-resolver"
	case "custom":
		p.Kind = "custom"
		p.Trust = "user-configured"
	case "flashstart":
		p.Kind = "negative-control"
		p.Trust = "lab"
	case "xbox-dns", "malw", "comss", "geohide", "controld-redirect":
		p.Kind = "smart-dns-gateway"
		p.Trust = "community"
		p.Scope = "lab"
		p.Experimental = true
		p.AllowedForAutoPilot = false
		p.AllowedForUSQUE = false
		p.USQUERegistration = "blocked"
		p.Warnings = append(p.Warnings, "Только сервисная диагностика по явному выбору. Не используется для регистрации WARP/USQUE. DNS-ответ не доказывает работу приложения.")
		if p.ID == "controld-redirect" {
			p.Trust = "account-required"
		}
		if p.ID == "xbox-dns" {
			p.DocumentationURL = "https://xbox-dns.ru/"
			p.DocumentationCheckedAt = "2026-09-13"
			p.ServiceHints = []string{"chatgpt", "gemini", "claude"}
		}
	}
	return p
}
