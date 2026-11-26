package strategylab

import (
	"encoding/json"
	"time"
)

// BuiltinPack contains two upstream examples, not a claim they work locally.
// Source: nfqws/nfqws2-keenetic c77226bd384e047a3d97e3ab6f0ad8b46fc3c967
// etc/nfqws2/nfqws2.conf; upstream MIT notice: docs/third-party/NFQWS_LICENSE.
// UDP voice's --out-range=<n2 is intentionally NOT approximated by this subset.
func BuiltinPack(now time.Time) []byte {
	tcp := `--filter-tcp=443,80,1984,5222 --filter-l7=http,tls,mtproto
--payload=tls_client_hello,mtproto_initial
--lua-desync=circular:fails=2:time=300:retrans=3:nld=2
--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000:strategy=1
--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up:strategy=1
--lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2:strategy=2
--lua-desync=multisplit:pos=1,midsld:strategy=2
--lua-desync=hostfakesplit:host=ozon.ru:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up:strategy=3
--lua-desync=hostfakesplit:tcp_md5:tcp_ts_up:strategy=3
--payload=http_req --lua-desync=http_methodeol:badsum`
	// Each generated local export has its own day-based identity; it is not an
	// online publisher version and never receives automatic update authority.
	p := StrategyPack{Schema: 1, ID: "nfqws-stock-" + now.UTC().Format("20060102"), Sequence: 1, IssuedAt: now.UTC().Truncate(24 * time.Hour), ExpiresAt: now.UTC().Truncate(24 * time.Hour).Add(30 * 24 * time.Hour), CompatibilityID: "nfqws2-zapret-auto-v1", Entries: []PackEntry{
		{PoolID: "tcp-tls", Name: "nfqws2-keenetic · TCP circular · c77226b", Arguments: tcp},
		{PoolID: "quic-udp", Name: "nfqws2-keenetic · QUIC fake · c77226b", Arguments: "--filter-udp=443 --filter-l7=quic --payload=quic_initial --lua-desync=fake:blob=quic_initial:repeats=11"},
	}}
	b, _ := json.MarshalIndent(p, "", "  ")
	return b
}
