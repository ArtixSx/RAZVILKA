package providerfeed

import "testing"

func TestLocalizedCountryLabelsRespectTransportAndNetworkBoundaries(t *testing.T) {
	for label, want := range map[string]string{
		"🇸🇪Швеция[TCP]": "SE", "🇵🇱Польша[WS]": "PL", "Poland(WS)": "PL", "Sweden [SS]": "SE",
		"Папуа — Новая Гвинея [TCP]": "PG", "Papua New Guinea": "PG", "Equatorial Guinea": "GQ",
		"South Georgia & South Sandwich Islands": "GS", "Северная Македония": "MK", "Албания": "AL",
		"Thailand [VLESS]": "TH", "Кыргызстан": "KG", "Объединенные Арабские Эмираты": "AE",
		"https://netherlands.example/path": "", "netherlands.example": "", "DE.example.org": "",
		"sni=Sweden": "", "SNI: Poland": "", "host: NL.example": "", "user@sweden.example": "",
		"example.com/Poland": "", "[WS]": "", "fakeSwedenSuffix": "", "ШвецияНеверно": "",
		"Sweden Poland": "", "🇸🇪 Poland [WS]": "", "Sweden | sni=poland.example": "SE",
		"CF": "", "[CF] [TLS]": "", "Cloudflare CF": "", "🇨🇫 CF": "CF", "Central African Republic [WS]": "CF",
		"Центрально-Африканская Республика": "CF", "RU SNI": "", "RU-SNI [TCP]": "", "RU_SNI NL": "NL", "🇷🇺 RU SNI": "RU",
	} {
		if got := inferCountry(label); got != want {
			t.Errorf("country label %q: got %q, want %q", label, got, want)
		}
	}
}

func TestLocalizedCountryDictionaryCoversAllowlistWithoutGuessing(t *testing.T) {
	seen := map[string]int{}
	for name, code := range countryLocaleNames {
		if !validCountry(code) {
			t.Fatal("localized name grants an unknown country")
		}
		if got := inferCountry(name); got != code {
			t.Errorf("localized country %q: got %q, want %q", name, got, code)
		}
		seen[code]++
	}
	for _, code := range countryCodes {
		if seen[code] != 2 {
			t.Errorf("country %s lacks a Russian or English label", code)
		}
	}
}
