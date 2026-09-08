package providerfeed

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

// Country is publisher-provided display metadata, never measured geography or
// route authority. Arbitrary publisher labels never enter the public response.
type Country struct {
	Code   string `json:"country_code"`
	Source string `json:"country_source"`
}

var countryCodes = strings.Fields("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW")
var countryNames = map[string]string{
	"netherlands": "NL", "нидерланды": "NL", "holland": "NL", "germany": "DE", "германия": "DE", "finland": "FI", "финляндия": "FI", "france": "FR", "франция": "FR", "sweden": "SE", "швеция": "SE", "switzerland": "CH", "швейцария": "CH", "poland": "PL", "польша": "PL", "russia": "RU", "россия": "RU", "usa": "US", "united states": "US", "сша": "US", "united kingdom": "GB", "великобритания": "GB", "uk": "GB", "japan": "JP", "япония": "JP", "singapore": "SG", "сингапур": "SG", "canada": "CA", "канада": "CA", "turkey": "TR", "türkiye": "TR", "турция": "TR", "estonia": "EE", "эстония": "EE", "latvia": "LV", "латвия": "LV", "lithuania": "LT", "литва": "LT", "ireland": "IE", "ирландия": "IE", "spain": "ES", "испания": "ES", "italy": "IT", "италия": "IT", "austria": "AT", "австрия": "AT", "belgium": "BE", "бельгия": "BE", "hong kong": "HK", "гонконг": "HK", "kazakhstan": "KZ", "казахстан": "KZ", "ukraine": "UA", "украина": "UA", "australia": "AU", "австралия": "AU", "czechia": "CZ", "czech republic": "CZ", "чехия": "CZ", "romania": "RO", "румыния": "RO", "norway": "NO", "норвегия": "NO", "denmark": "DK", "дания": "DK", "brazil": "BR", "бразилия": "BR", "india": "IN", "индия": "IN", "south korea": "KR", "корея": "KR"}

var countryTransportMarker = regexp.MustCompile(`(?i)[\[(](tcp|ws|websocket|grpc|http|http2|h2|xhttp|ss|vless|vmess|trojan|reality|tls|hy2|hysteria2|tuic)[\])]`)
var countrySNICategory = regexp.MustCompile(`(?i)\bRU[ _-]*SNI\b`)

var countryNameTokens, maxCountryNameWords = buildCountryNameTokens()

func countryWords(label string) []string {
	return strings.FieldsFunc(label, func(r rune) bool { return !unicode.IsLetter(r) })
}

func buildCountryNameTokens() (map[string]string, int) {
	names := make(map[string]string, len(countryLocaleNames)+len(countryNames))
	maxWords := 1
	for _, source := range []map[string]string{countryLocaleNames, countryNames, {
		"кыргызстан": "KG", "объединенные арабские эмираты": "AE", "объединённые арабские эмираты": "AE",
		"южная корея": "KR", "соединенные штаты америки": "US", "соединённые штаты америки": "US",
		"соединенное королевство": "GB", "соединённое королевство": "GB",
	}} {
		for name, code := range source {
			words := countryWords(strings.ToLower(name))
			key := strings.Join(words, " ")
			if prior, found := names[key]; found && prior != code {
				names[key] = "" // Ambiguous labels cannot choose a country.
			} else {
				names[key] = code
			}
			maxWords = max(maxWords, len(words))
		}
	}
	return names, maxWords
}

func countryDisplayLabel(label string) string {
	label = countryTransportMarker.ReplaceAllString(label, " ")
	label = countrySNICategory.ReplaceAllString(label, " ")
	parts := strings.FieldsFunc(label, func(r rune) bool { return unicode.IsSpace(r) || r == '|' || r == ',' })
	kept := make([]string, 0, len(parts))
	skipNext := false
	for _, part := range parts {
		if skipNext {
			skipNext = false
			continue
		}
		switch strings.ToLower(strings.Trim(part, "[]()")) {
		case "sni:", "host:", "server:", "endpoint:", "address:":
			skipNext = true
			continue
		}
		// Country-looking tokens inside a host, URI, SNI or query parameter
		// are not geographic labels. Transport [WS] is not the ISO code WS.
		abbreviation := strings.ToLower(part)
		if strings.ContainsAny(part, ".:/\\@=") && abbreviation != "st." && abbreviation != "u.s." && abbreviation != "св." {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, " ")
}

func validCountry(code string) bool {
	for _, known := range countryCodes {
		if code == known {
			return true
		}
	}
	return false
}
func inferCountry(label string) string {
	if len(label) > 512 {
		return ""
	}
	label = countryDisplayLabel(label)
	found := ""
	add := func(code string) bool {
		if !validCountry(code) {
			return true
		}
		if found != "" && found != code {
			return false
		}
		found = code
		return true
	}
	runes := []rune(label)
	for i := 0; i+1 < len(runes); i++ {
		if runes[i] >= 0x1F1E6 && runes[i] <= 0x1F1FF && runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
			if !add(string([]rune{'A' + runes[i] - 0x1F1E6, 'A' + runes[i+1] - 0x1F1E6})) {
				return ""
			}
			i++
		}
	}
	tokens := countryWords(label)
	for index := 0; index < len(tokens); {
		matched := false
		// Prefer complete names over contained countries: Papua New Guinea
		// does not also mean Guinea, and South Georgia does not mean Georgia.
		for count := min(maxCountryNameWords, len(tokens)-index); count > 0; count-- {
			key := strings.ToLower(strings.Join(tokens[index:index+count], " "))
			if code, exists := countryNameTokens[key]; exists {
				if code == "" || !add(code) {
					return ""
				}
				index += count
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		token := tokens[index]
		// Public subscriptions commonly use bare CF for Cloudflare. Require
		// its explicit flag or full country name instead of guessing geography.
		if len(token) == 2 && token != "CF" && token == strings.ToUpper(token) && !add(token) {
			return ""
		}
		index++
	}
	return found
}

func onlyCountrySource(origins []string, sourceID string) bool {
	if len(origins) == 0 {
		return false
	}
	for _, origin := range origins {
		if origin != sourceID {
			return false
		}
	}
	return true
}
func (m *Manager) CountryMetadata() map[string]Country {
	out := map[string]Country{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storage != nil {
		for id, code := range m.storage.doc.Countries {
			out[id] = Country{Code: code, Source: "publisher"}
		}
	}
	return out
}
func canonicalOutbound(raw json.RawMessage) (json.RawMessage, error) {
	var outbound map[string]any
	if err := json.Unmarshal(raw, &outbound); err != nil {
		return nil, err
	}
	delete(outbound, "tag")
	return json.Marshal(outbound)
}
