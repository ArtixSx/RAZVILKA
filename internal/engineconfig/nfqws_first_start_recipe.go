package engineconfig

// NFQWSFirstStartRecipe selects a closed compiler recipe, never caller argv.
// The zero value preserves the exact original v1 representation.
type NFQWSFirstStartRecipe string

const (
	NFQWSFirstStartStockTLSCircular NFQWSFirstStartRecipe = "stock-tls-circular-v1"
	// The universal 1.3.1 package already implements this upstream mode.
	// Keep it a separate identity: existing receipts retain fastpath=0.
	NFQWSFirstStartStockTLSCircularAuto NFQWSFirstStartRecipe = "stock-tls-circular-auto-v1"
	// Observer callbacks must see bounded replies before payload/direction are
	// narrowed for tampering. Separate identity preserves every existing receipt.
	NFQWSFirstStartStockTLSCircularObserveAuto NFQWSFirstStartRecipe = "stock-tls-circular-observe-auto-v1"
)

func (r NFQWSFirstStartRecipe) Valid() bool {
	return r == "" || r == NFQWSFirstStartStockTLSCircular || r == NFQWSFirstStartStockTLSCircularAuto || r == NFQWSFirstStartStockTLSCircularObserveAuto
}

const NFQWSFirstStartFormatV2 = "# RAZVILKA NFQWS2 TCP443 STARTER v2"

// Exact TLS strategy chain from nfqws2-keenetic c77226bd384e047a3d97e3ab6f0ad8b46fc3c967,
// also retained in the reviewed 1.3.1 stock config. Only the transport/payload
// filters are narrowed: no HTTP, MTProto, UDP or additional destination ports.
const nfqwsFirstStartStockTLSCircularArgs = "--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello " +
	"--lua-desync=circular:fails=2:time=300:retrans=3:nld=2 " + nfqwsFirstStartStockTLSCircularStrategies

// The old strategy chain is byte-for-byte unchanged and remains restricted to
// outgoing ClientHello by the envelope. No incoming packet reaches a mutator.
const nfqwsFirstStartStockTLSCircularObserveArgs = "--filter-tcp=443 --filter-l7=tls --in-range=-s5556 --payload=all " +
	"--lua-desync=circular:fails=2:time=300:retrans=3:nld=2 " +
	"--in-range=x --payload=tls_client_hello " + nfqwsFirstStartStockTLSCircularStrategies

const nfqwsFirstStartStockTLSCircularStrategies = "--lua-desync=fake:blob=tls_clienthello:tls_mod=rnd,dupsid,sni=fonts.google.com:tcp_seq=10000:strategy=1 " +
	"--lua-desync=multisplit:pos=1,midsld:seqovl=1:seqovl_pattern=tls_clienthello:tcp_ts_up:strategy=1 " +
	"--lua-desync=fake:blob=0x00000000:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com:repeats=2:strategy=2 " +
	"--lua-desync=multisplit:pos=1,midsld:strategy=2 " +
	"--lua-desync=hostfakesplit:host=ozon.ru:midhost=host-2:seqovl=sniext+3:seqovl_pattern=tls_clienthello:badsum:tcp_md5:tcp_ts_up:strategy=3 " +
	"--lua-desync=hostfakesplit:tcp_md5:tcp_ts_up:strategy=3"
