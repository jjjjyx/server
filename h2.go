package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/idna"
)

// The HTTP protocols are defined in terms of ASCII, not Unicode. This file
// contains helper functions which may use Unicode-aware functions which would
// otherwise be unsafe and could introduce vulnerabilities if used improperly.

// asciiEqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func http2asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if http2lower(s[i]) != http2lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func http2lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// isASCIIPrint returns whether s is ASCII and printable according to
// https://tools.ietf.org/html/rfc20#section-4.2.
func http2isASCIIPrint(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// asciiToLower returns the lowercase version of s if s is ASCII and printable,
// and whether or not it was.
func http2asciiToLower(s string) (lower string, ok bool) {
	if !http2isASCIIPrint(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

// A list of the possible cipher suite ids. Taken from
// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt

const (
	http2cipher_TLS_NULL_WITH_NULL_NULL               uint16 = 0x0000
	http2cipher_TLS_RSA_WITH_NULL_MD5                 uint16 = 0x0001
	http2cipher_TLS_RSA_WITH_NULL_SHA                 uint16 = 0x0002
	http2cipher_TLS_RSA_EXPORT_WITH_RC4_40_MD5        uint16 = 0x0003
	http2cipher_TLS_RSA_WITH_RC4_128_MD5              uint16 = 0x0004
	http2cipher_TLS_RSA_WITH_RC4_128_SHA              uint16 = 0x0005
	http2cipher_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    uint16 = 0x0006
	http2cipher_TLS_RSA_WITH_IDEA_CBC_SHA             uint16 = 0x0007
	http2cipher_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     uint16 = 0x0008
	http2cipher_TLS_RSA_WITH_DES_CBC_SHA              uint16 = 0x0009
	http2cipher_TLS_RSA_WITH_3DES_EDE_CBC_SHA         uint16 = 0x000A
	http2cipher_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  uint16 = 0x000B
	http2cipher_TLS_DH_DSS_WITH_DES_CBC_SHA           uint16 = 0x000C
	http2cipher_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      uint16 = 0x000D
	http2cipher_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  uint16 = 0x000E
	http2cipher_TLS_DH_RSA_WITH_DES_CBC_SHA           uint16 = 0x000F
	http2cipher_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      uint16 = 0x0010
	http2cipher_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA uint16 = 0x0011
	http2cipher_TLS_DHE_DSS_WITH_DES_CBC_SHA          uint16 = 0x0012
	http2cipher_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     uint16 = 0x0013
	http2cipher_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA uint16 = 0x0014
	http2cipher_TLS_DHE_RSA_WITH_DES_CBC_SHA          uint16 = 0x0015
	http2cipher_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0x0016
	http2cipher_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    uint16 = 0x0017
	http2cipher_TLS_DH_anon_WITH_RC4_128_MD5          uint16 = 0x0018
	http2cipher_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA uint16 = 0x0019
	http2cipher_TLS_DH_anon_WITH_DES_CBC_SHA          uint16 = 0x001A
	http2cipher_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     uint16 = 0x001B
	// Reserved uint16 =  0x001C-1D
	http2cipher_TLS_KRB5_WITH_DES_CBC_SHA             uint16 = 0x001E
	http2cipher_TLS_KRB5_WITH_3DES_EDE_CBC_SHA        uint16 = 0x001F
	http2cipher_TLS_KRB5_WITH_RC4_128_SHA             uint16 = 0x0020
	http2cipher_TLS_KRB5_WITH_IDEA_CBC_SHA            uint16 = 0x0021
	http2cipher_TLS_KRB5_WITH_DES_CBC_MD5             uint16 = 0x0022
	http2cipher_TLS_KRB5_WITH_3DES_EDE_CBC_MD5        uint16 = 0x0023
	http2cipher_TLS_KRB5_WITH_RC4_128_MD5             uint16 = 0x0024
	http2cipher_TLS_KRB5_WITH_IDEA_CBC_MD5            uint16 = 0x0025
	http2cipher_TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA   uint16 = 0x0026
	http2cipher_TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA   uint16 = 0x0027
	http2cipher_TLS_KRB5_EXPORT_WITH_RC4_40_SHA       uint16 = 0x0028
	http2cipher_TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5   uint16 = 0x0029
	http2cipher_TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5   uint16 = 0x002A
	http2cipher_TLS_KRB5_EXPORT_WITH_RC4_40_MD5       uint16 = 0x002B
	http2cipher_TLS_PSK_WITH_NULL_SHA                 uint16 = 0x002C
	http2cipher_TLS_DHE_PSK_WITH_NULL_SHA             uint16 = 0x002D
	http2cipher_TLS_RSA_PSK_WITH_NULL_SHA             uint16 = 0x002E
	http2cipher_TLS_RSA_WITH_AES_128_CBC_SHA          uint16 = 0x002F
	http2cipher_TLS_DH_DSS_WITH_AES_128_CBC_SHA       uint16 = 0x0030
	http2cipher_TLS_DH_RSA_WITH_AES_128_CBC_SHA       uint16 = 0x0031
	http2cipher_TLS_DHE_DSS_WITH_AES_128_CBC_SHA      uint16 = 0x0032
	http2cipher_TLS_DHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0x0033
	http2cipher_TLS_DH_anon_WITH_AES_128_CBC_SHA      uint16 = 0x0034
	http2cipher_TLS_RSA_WITH_AES_256_CBC_SHA          uint16 = 0x0035
	http2cipher_TLS_DH_DSS_WITH_AES_256_CBC_SHA       uint16 = 0x0036
	http2cipher_TLS_DH_RSA_WITH_AES_256_CBC_SHA       uint16 = 0x0037
	http2cipher_TLS_DHE_DSS_WITH_AES_256_CBC_SHA      uint16 = 0x0038
	http2cipher_TLS_DHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0x0039
	http2cipher_TLS_DH_anon_WITH_AES_256_CBC_SHA      uint16 = 0x003A
	http2cipher_TLS_RSA_WITH_NULL_SHA256              uint16 = 0x003B
	http2cipher_TLS_RSA_WITH_AES_128_CBC_SHA256       uint16 = 0x003C
	http2cipher_TLS_RSA_WITH_AES_256_CBC_SHA256       uint16 = 0x003D
	http2cipher_TLS_DH_DSS_WITH_AES_128_CBC_SHA256    uint16 = 0x003E
	http2cipher_TLS_DH_RSA_WITH_AES_128_CBC_SHA256    uint16 = 0x003F
	http2cipher_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   uint16 = 0x0040
	http2cipher_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA     uint16 = 0x0041
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA  uint16 = 0x0042
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA  uint16 = 0x0043
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA uint16 = 0x0044
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA uint16 = 0x0045
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA uint16 = 0x0046
	// Reserved uint16 =  0x0047-4F
	// Reserved uint16 =  0x0050-58
	// Reserved uint16 =  0x0059-5C
	// Unassigned uint16 =  0x005D-5F
	// Reserved uint16 =  0x0060-66
	http2cipher_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 uint16 = 0x0067
	http2cipher_TLS_DH_DSS_WITH_AES_256_CBC_SHA256  uint16 = 0x0068
	http2cipher_TLS_DH_RSA_WITH_AES_256_CBC_SHA256  uint16 = 0x0069
	http2cipher_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 uint16 = 0x006A
	http2cipher_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 uint16 = 0x006B
	http2cipher_TLS_DH_anon_WITH_AES_128_CBC_SHA256 uint16 = 0x006C
	http2cipher_TLS_DH_anon_WITH_AES_256_CBC_SHA256 uint16 = 0x006D
	// Unassigned uint16 =  0x006E-83
	http2cipher_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        uint16 = 0x0084
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA     uint16 = 0x0085
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA     uint16 = 0x0086
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0087
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0088
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0089
	http2cipher_TLS_PSK_WITH_RC4_128_SHA                 uint16 = 0x008A
	http2cipher_TLS_PSK_WITH_3DES_EDE_CBC_SHA            uint16 = 0x008B
	http2cipher_TLS_PSK_WITH_AES_128_CBC_SHA             uint16 = 0x008C
	http2cipher_TLS_PSK_WITH_AES_256_CBC_SHA             uint16 = 0x008D
	http2cipher_TLS_DHE_PSK_WITH_RC4_128_SHA             uint16 = 0x008E
	http2cipher_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA        uint16 = 0x008F
	http2cipher_TLS_DHE_PSK_WITH_AES_128_CBC_SHA         uint16 = 0x0090
	http2cipher_TLS_DHE_PSK_WITH_AES_256_CBC_SHA         uint16 = 0x0091
	http2cipher_TLS_RSA_PSK_WITH_RC4_128_SHA             uint16 = 0x0092
	http2cipher_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA        uint16 = 0x0093
	http2cipher_TLS_RSA_PSK_WITH_AES_128_CBC_SHA         uint16 = 0x0094
	http2cipher_TLS_RSA_PSK_WITH_AES_256_CBC_SHA         uint16 = 0x0095
	http2cipher_TLS_RSA_WITH_SEED_CBC_SHA                uint16 = 0x0096
	http2cipher_TLS_DH_DSS_WITH_SEED_CBC_SHA             uint16 = 0x0097
	http2cipher_TLS_DH_RSA_WITH_SEED_CBC_SHA             uint16 = 0x0098
	http2cipher_TLS_DHE_DSS_WITH_SEED_CBC_SHA            uint16 = 0x0099
	http2cipher_TLS_DHE_RSA_WITH_SEED_CBC_SHA            uint16 = 0x009A
	http2cipher_TLS_DH_anon_WITH_SEED_CBC_SHA            uint16 = 0x009B
	http2cipher_TLS_RSA_WITH_AES_128_GCM_SHA256          uint16 = 0x009C
	http2cipher_TLS_RSA_WITH_AES_256_GCM_SHA384          uint16 = 0x009D
	http2cipher_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      uint16 = 0x009E
	http2cipher_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      uint16 = 0x009F
	http2cipher_TLS_DH_RSA_WITH_AES_128_GCM_SHA256       uint16 = 0x00A0
	http2cipher_TLS_DH_RSA_WITH_AES_256_GCM_SHA384       uint16 = 0x00A1
	http2cipher_TLS_DHE_DSS_WITH_AES_128_GCM_SHA256      uint16 = 0x00A2
	http2cipher_TLS_DHE_DSS_WITH_AES_256_GCM_SHA384      uint16 = 0x00A3
	http2cipher_TLS_DH_DSS_WITH_AES_128_GCM_SHA256       uint16 = 0x00A4
	http2cipher_TLS_DH_DSS_WITH_AES_256_GCM_SHA384       uint16 = 0x00A5
	http2cipher_TLS_DH_anon_WITH_AES_128_GCM_SHA256      uint16 = 0x00A6
	http2cipher_TLS_DH_anon_WITH_AES_256_GCM_SHA384      uint16 = 0x00A7
	http2cipher_TLS_PSK_WITH_AES_128_GCM_SHA256          uint16 = 0x00A8
	http2cipher_TLS_PSK_WITH_AES_256_GCM_SHA384          uint16 = 0x00A9
	http2cipher_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      uint16 = 0x00AA
	http2cipher_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      uint16 = 0x00AB
	http2cipher_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256      uint16 = 0x00AC
	http2cipher_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384      uint16 = 0x00AD
	http2cipher_TLS_PSK_WITH_AES_128_CBC_SHA256          uint16 = 0x00AE
	http2cipher_TLS_PSK_WITH_AES_256_CBC_SHA384          uint16 = 0x00AF
	http2cipher_TLS_PSK_WITH_NULL_SHA256                 uint16 = 0x00B0
	http2cipher_TLS_PSK_WITH_NULL_SHA384                 uint16 = 0x00B1
	http2cipher_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256      uint16 = 0x00B2
	http2cipher_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384      uint16 = 0x00B3
	http2cipher_TLS_DHE_PSK_WITH_NULL_SHA256             uint16 = 0x00B4
	http2cipher_TLS_DHE_PSK_WITH_NULL_SHA384             uint16 = 0x00B5
	http2cipher_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256      uint16 = 0x00B6
	http2cipher_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384      uint16 = 0x00B7
	http2cipher_TLS_RSA_PSK_WITH_NULL_SHA256             uint16 = 0x00B8
	http2cipher_TLS_RSA_PSK_WITH_NULL_SHA384             uint16 = 0x00B9
	http2cipher_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     uint16 = 0x00BA
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256  uint16 = 0x00BB
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256  uint16 = 0x00BC
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00BD
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00BE
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00BF
	http2cipher_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     uint16 = 0x00C0
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256  uint16 = 0x00C1
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256  uint16 = 0x00C2
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00C3
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00C4
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00C5
	// Unassigned uint16 =  0x00C6-FE
	http2cipher_TLS_EMPTY_RENEGOTIATION_INFO_SCSV uint16 = 0x00FF
	// Unassigned uint16 =  0x01-55,*
	http2cipher_TLS_FALLBACK_SCSV uint16 = 0x5600
	// Unassigned                                   uint16 = 0x5601 - 0xC000
	http2cipher_TLS_ECDH_ECDSA_WITH_NULL_SHA                 uint16 = 0xC001
	http2cipher_TLS_ECDH_ECDSA_WITH_RC4_128_SHA              uint16 = 0xC002
	http2cipher_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA         uint16 = 0xC003
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xC004
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xC005
	http2cipher_TLS_ECDHE_ECDSA_WITH_NULL_SHA                uint16 = 0xC006
	http2cipher_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA             uint16 = 0xC007
	http2cipher_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA        uint16 = 0xC008
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA         uint16 = 0xC009
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA         uint16 = 0xC00A
	http2cipher_TLS_ECDH_RSA_WITH_NULL_SHA                   uint16 = 0xC00B
	http2cipher_TLS_ECDH_RSA_WITH_RC4_128_SHA                uint16 = 0xC00C
	http2cipher_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xC00D
	http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xC00E
	http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xC00F
	http2cipher_TLS_ECDHE_RSA_WITH_NULL_SHA                  uint16 = 0xC010
	http2cipher_TLS_ECDHE_RSA_WITH_RC4_128_SHA               uint16 = 0xC011
	http2cipher_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA          uint16 = 0xC012
	http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA           uint16 = 0xC013
	http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA           uint16 = 0xC014
	http2cipher_TLS_ECDH_anon_WITH_NULL_SHA                  uint16 = 0xC015
	http2cipher_TLS_ECDH_anon_WITH_RC4_128_SHA               uint16 = 0xC016
	http2cipher_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA          uint16 = 0xC017
	http2cipher_TLS_ECDH_anon_WITH_AES_128_CBC_SHA           uint16 = 0xC018
	http2cipher_TLS_ECDH_anon_WITH_AES_256_CBC_SHA           uint16 = 0xC019
	http2cipher_TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA            uint16 = 0xC01A
	http2cipher_TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA        uint16 = 0xC01B
	http2cipher_TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA        uint16 = 0xC01C
	http2cipher_TLS_SRP_SHA_WITH_AES_128_CBC_SHA             uint16 = 0xC01D
	http2cipher_TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA         uint16 = 0xC01E
	http2cipher_TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA         uint16 = 0xC01F
	http2cipher_TLS_SRP_SHA_WITH_AES_256_CBC_SHA             uint16 = 0xC020
	http2cipher_TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA         uint16 = 0xC021
	http2cipher_TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA         uint16 = 0xC022
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256      uint16 = 0xC023
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384      uint16 = 0xC024
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xC025
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384       uint16 = 0xC026
	http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256        uint16 = 0xC027
	http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384        uint16 = 0xC028
	http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xC029
	http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384         uint16 = 0xC02A
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256      uint16 = 0xC02B
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384      uint16 = 0xC02C
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xC02D
	http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xC02E
	http2cipher_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256        uint16 = 0xC02F
	http2cipher_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384        uint16 = 0xC030
	http2cipher_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xC031
	http2cipher_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xC032
	http2cipher_TLS_ECDHE_PSK_WITH_RC4_128_SHA               uint16 = 0xC033
	http2cipher_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA          uint16 = 0xC034
	http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA           uint16 = 0xC035
	http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA           uint16 = 0xC036
	http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256        uint16 = 0xC037
	http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384        uint16 = 0xC038
	http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA                  uint16 = 0xC039
	http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA256               uint16 = 0xC03A
	http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA384               uint16 = 0xC03B
	http2cipher_TLS_RSA_WITH_ARIA_128_CBC_SHA256             uint16 = 0xC03C
	http2cipher_TLS_RSA_WITH_ARIA_256_CBC_SHA384             uint16 = 0xC03D
	http2cipher_TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256          uint16 = 0xC03E
	http2cipher_TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384          uint16 = 0xC03F
	http2cipher_TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256          uint16 = 0xC040
	http2cipher_TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384          uint16 = 0xC041
	http2cipher_TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256         uint16 = 0xC042
	http2cipher_TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384         uint16 = 0xC043
	http2cipher_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256         uint16 = 0xC044
	http2cipher_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384         uint16 = 0xC045
	http2cipher_TLS_DH_anon_WITH_ARIA_128_CBC_SHA256         uint16 = 0xC046
	http2cipher_TLS_DH_anon_WITH_ARIA_256_CBC_SHA384         uint16 = 0xC047
	http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256     uint16 = 0xC048
	http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384     uint16 = 0xC049
	http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256      uint16 = 0xC04A
	http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384      uint16 = 0xC04B
	http2cipher_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256       uint16 = 0xC04C
	http2cipher_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384       uint16 = 0xC04D
	http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256        uint16 = 0xC04E
	http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384        uint16 = 0xC04F
	http2cipher_TLS_RSA_WITH_ARIA_128_GCM_SHA256             uint16 = 0xC050
	http2cipher_TLS_RSA_WITH_ARIA_256_GCM_SHA384             uint16 = 0xC051
	http2cipher_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256         uint16 = 0xC052
	http2cipher_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384         uint16 = 0xC053
	http2cipher_TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256          uint16 = 0xC054
	http2cipher_TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384          uint16 = 0xC055
	http2cipher_TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256         uint16 = 0xC056
	http2cipher_TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384         uint16 = 0xC057
	http2cipher_TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256          uint16 = 0xC058
	http2cipher_TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384          uint16 = 0xC059
	http2cipher_TLS_DH_anon_WITH_ARIA_128_GCM_SHA256         uint16 = 0xC05A
	http2cipher_TLS_DH_anon_WITH_ARIA_256_GCM_SHA384         uint16 = 0xC05B
	http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     uint16 = 0xC05C
	http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     uint16 = 0xC05D
	http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      uint16 = 0xC05E
	http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      uint16 = 0xC05F
	http2cipher_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       uint16 = 0xC060
	http2cipher_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       uint16 = 0xC061
	http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        uint16 = 0xC062
	http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        uint16 = 0xC063
	http2cipher_TLS_PSK_WITH_ARIA_128_CBC_SHA256             uint16 = 0xC064
	http2cipher_TLS_PSK_WITH_ARIA_256_CBC_SHA384             uint16 = 0xC065
	http2cipher_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256         uint16 = 0xC066
	http2cipher_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384         uint16 = 0xC067
	http2cipher_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256         uint16 = 0xC068
	http2cipher_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384         uint16 = 0xC069
	http2cipher_TLS_PSK_WITH_ARIA_128_GCM_SHA256             uint16 = 0xC06A
	http2cipher_TLS_PSK_WITH_ARIA_256_GCM_SHA384             uint16 = 0xC06B
	http2cipher_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256         uint16 = 0xC06C
	http2cipher_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384         uint16 = 0xC06D
	http2cipher_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256         uint16 = 0xC06E
	http2cipher_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384         uint16 = 0xC06F
	http2cipher_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256       uint16 = 0xC070
	http2cipher_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384       uint16 = 0xC071
	http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0xC072
	http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 uint16 = 0xC073
	http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  uint16 = 0xC074
	http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  uint16 = 0xC075
	http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   uint16 = 0xC076
	http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   uint16 = 0xC077
	http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    uint16 = 0xC078
	http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    uint16 = 0xC079
	http2cipher_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         uint16 = 0xC07A
	http2cipher_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         uint16 = 0xC07B
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     uint16 = 0xC07C
	http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     uint16 = 0xC07D
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256      uint16 = 0xC07E
	http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384      uint16 = 0xC07F
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256     uint16 = 0xC080
	http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384     uint16 = 0xC081
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256      uint16 = 0xC082
	http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384      uint16 = 0xC083
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256     uint16 = 0xC084
	http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384     uint16 = 0xC085
	http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 uint16 = 0xC086
	http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 uint16 = 0xC087
	http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  uint16 = 0xC088
	http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  uint16 = 0xC089
	http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   uint16 = 0xC08A
	http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   uint16 = 0xC08B
	http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    uint16 = 0xC08C
	http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    uint16 = 0xC08D
	http2cipher_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256         uint16 = 0xC08E
	http2cipher_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384         uint16 = 0xC08F
	http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256     uint16 = 0xC090
	http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384     uint16 = 0xC091
	http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256     uint16 = 0xC092
	http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384     uint16 = 0xC093
	http2cipher_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256         uint16 = 0xC094
	http2cipher_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384         uint16 = 0xC095
	http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     uint16 = 0xC096
	http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     uint16 = 0xC097
	http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256     uint16 = 0xC098
	http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384     uint16 = 0xC099
	http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   uint16 = 0xC09A
	http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   uint16 = 0xC09B
	http2cipher_TLS_RSA_WITH_AES_128_CCM                     uint16 = 0xC09C
	http2cipher_TLS_RSA_WITH_AES_256_CCM                     uint16 = 0xC09D
	http2cipher_TLS_DHE_RSA_WITH_AES_128_CCM                 uint16 = 0xC09E
	http2cipher_TLS_DHE_RSA_WITH_AES_256_CCM                 uint16 = 0xC09F
	http2cipher_TLS_RSA_WITH_AES_128_CCM_8                   uint16 = 0xC0A0
	http2cipher_TLS_RSA_WITH_AES_256_CCM_8                   uint16 = 0xC0A1
	http2cipher_TLS_DHE_RSA_WITH_AES_128_CCM_8               uint16 = 0xC0A2
	http2cipher_TLS_DHE_RSA_WITH_AES_256_CCM_8               uint16 = 0xC0A3
	http2cipher_TLS_PSK_WITH_AES_128_CCM                     uint16 = 0xC0A4
	http2cipher_TLS_PSK_WITH_AES_256_CCM                     uint16 = 0xC0A5
	http2cipher_TLS_DHE_PSK_WITH_AES_128_CCM                 uint16 = 0xC0A6
	http2cipher_TLS_DHE_PSK_WITH_AES_256_CCM                 uint16 = 0xC0A7
	http2cipher_TLS_PSK_WITH_AES_128_CCM_8                   uint16 = 0xC0A8
	http2cipher_TLS_PSK_WITH_AES_256_CCM_8                   uint16 = 0xC0A9
	http2cipher_TLS_PSK_DHE_WITH_AES_128_CCM_8               uint16 = 0xC0AA
	http2cipher_TLS_PSK_DHE_WITH_AES_256_CCM_8               uint16 = 0xC0AB
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CCM             uint16 = 0xC0AC
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CCM             uint16 = 0xC0AD
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8           uint16 = 0xC0AE
	http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8           uint16 = 0xC0AF
	// Unassigned uint16 =  0xC0B0-FF
	// Unassigned uint16 =  0xC1-CB,*
	// Unassigned uint16 =  0xCC00-A7
	http2cipher_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xCCA8
	http2cipher_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xCCA9
	http2cipher_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     uint16 = 0xCCAA
	http2cipher_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         uint16 = 0xCCAB
	http2cipher_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xCCAC
	http2cipher_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     uint16 = 0xCCAD
	http2cipher_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     uint16 = 0xCCAE
)

// isBadCipher reports whether the cipher is blacklisted by the HTTP/2 spec.
// References:
// https://tools.ietf.org/html/rfc7540#appendix-A
// Reject cipher suites from Appendix A.
// "This list includes those cipher suites that do not
// offer an ephemeral key exchange and those that are
// based on the TLS null, stream or block cipher type"
func http2isBadCipher(cipher uint16) bool {
	switch cipher {
	case http2cipher_TLS_NULL_WITH_NULL_NULL,
		http2cipher_TLS_RSA_WITH_NULL_MD5,
		http2cipher_TLS_RSA_WITH_NULL_SHA,
		http2cipher_TLS_RSA_EXPORT_WITH_RC4_40_MD5,
		http2cipher_TLS_RSA_WITH_RC4_128_MD5,
		http2cipher_TLS_RSA_WITH_RC4_128_SHA,
		http2cipher_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
		http2cipher_TLS_RSA_WITH_IDEA_CBC_SHA,
		http2cipher_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_RSA_WITH_DES_CBC_SHA,
		http2cipher_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_DES_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_DES_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_DES_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_DES_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
		http2cipher_TLS_DH_anon_WITH_RC4_128_MD5,
		http2cipher_TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_DES_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_KRB5_WITH_DES_CBC_SHA,
		http2cipher_TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_KRB5_WITH_RC4_128_SHA,
		http2cipher_TLS_KRB5_WITH_IDEA_CBC_SHA,
		http2cipher_TLS_KRB5_WITH_DES_CBC_MD5,
		http2cipher_TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
		http2cipher_TLS_KRB5_WITH_RC4_128_MD5,
		http2cipher_TLS_KRB5_WITH_IDEA_CBC_MD5,
		http2cipher_TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
		http2cipher_TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
		http2cipher_TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
		http2cipher_TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
		http2cipher_TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
		http2cipher_TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
		http2cipher_TLS_PSK_WITH_NULL_SHA,
		http2cipher_TLS_DHE_PSK_WITH_NULL_SHA,
		http2cipher_TLS_RSA_PSK_WITH_NULL_SHA,
		http2cipher_TLS_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_RSA_WITH_NULL_SHA256,
		http2cipher_TLS_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_AES_256_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
		http2cipher_TLS_PSK_WITH_RC4_128_SHA,
		http2cipher_TLS_PSK_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_PSK_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_PSK_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_DHE_PSK_WITH_RC4_128_SHA,
		http2cipher_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_RSA_PSK_WITH_RC4_128_SHA,
		http2cipher_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_RSA_WITH_SEED_CBC_SHA,
		http2cipher_TLS_DH_DSS_WITH_SEED_CBC_SHA,
		http2cipher_TLS_DH_RSA_WITH_SEED_CBC_SHA,
		http2cipher_TLS_DHE_DSS_WITH_SEED_CBC_SHA,
		http2cipher_TLS_DHE_RSA_WITH_SEED_CBC_SHA,
		http2cipher_TLS_DH_anon_WITH_SEED_CBC_SHA,
		http2cipher_TLS_RSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_RSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_DH_anon_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_DH_anon_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_PSK_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_PSK_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_PSK_WITH_NULL_SHA256,
		http2cipher_TLS_PSK_WITH_NULL_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_NULL_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_NULL_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_NULL_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_NULL_SHA384,
		http2cipher_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		http2cipher_TLS_ECDH_ECDSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_anon_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA384,
		http2cipher_TLS_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_PSK_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_PSK_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_AES_128_CCM,
		http2cipher_TLS_RSA_WITH_AES_256_CCM,
		http2cipher_TLS_RSA_WITH_AES_128_CCM_8,
		http2cipher_TLS_RSA_WITH_AES_256_CCM_8,
		http2cipher_TLS_PSK_WITH_AES_128_CCM,
		http2cipher_TLS_PSK_WITH_AES_256_CCM,
		http2cipher_TLS_PSK_WITH_AES_128_CCM_8,
		http2cipher_TLS_PSK_WITH_AES_256_CCM_8:
		return true
	default:
		return false
	}
}

// ClientConnPool manages a pool of HTTP/2 client connections.
type http2ClientConnPool interface {
	// GetClientConn returns a specific HTTP/2 connection (usually
	// a TLS-TCP connection) to an HTTP/2 server. On success, the
	// returned ClientConn accounts for the upcoming RoundTrip
	// call, so the caller should not omit it. If the caller needs
	// to, ClientConn.RoundTrip can be called with a bogus
	// new(http.Request) to release the stream reservation.
	GetClientConn(req *http.Request, addr string) (*http2ClientConn, error)
	MarkDead(*http2ClientConn)
}

// clientConnPoolIdleCloser is the interface implemented by ClientConnPool
// implementations which can close their idle connections.
type http2clientConnPoolIdleCloser interface {
	http2ClientConnPool
	closeIdleConnections()
}

var (
	_ http2clientConnPoolIdleCloser = (*http2clientConnPool)(nil)
	_ http2clientConnPoolIdleCloser = http2noDialClientConnPool{}
)

// TODO: use singleflight for dialing and addConnCalls?
type http2clientConnPool struct {
	t *http2Transport

	mu sync.Mutex // TODO: maybe switch to RWMutex
	// TODO: add support for sharing conns based on cert names
	// (e.g. share conn for googleapis.com and appspot.com)
	conns        map[string][]*http2ClientConn // key is host:port
	dialing      map[string]*http2dialCall     // currently in-flight dials
	keys         map[*http2ClientConn][]string
	addConnCalls map[string]*http2addConnCall // in-flight addConnIfNeeded calls
}

func (p *http2clientConnPool) GetClientConn(req *http.Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2dialOnMiss)
}

const (
	http2dialOnMiss   = true
	http2noDialOnMiss = false
)

func (p *http2clientConnPool) getClientConn(req *http.Request, addr string, dialOnMiss bool) (*http2ClientConn, error) {
	// TODO(dneil): Dial a new connection when t.DisableKeepAlives is set?
	if http2isConnectionCloseRequest(req) && dialOnMiss {
		// It gets its own connection.
		http2traceGetConn(req, addr)
		const singleUse = true
		cc, err := p.t.dialClientConn(req.Context(), addr, singleUse)
		if err != nil {
			return nil, err
		}
		return cc, nil
	}
	for {
		p.mu.Lock()
		for _, cc := range p.conns[addr] {
			if cc.ReserveNewRequest() {
				// When a connection is presented to us by the net/http package,
				// the GetConn hook has already been called.
				// Don't call it a second time here.
				if !cc.getConnCalled {
					http2traceGetConn(req, addr)
				}
				cc.getConnCalled = false
				p.mu.Unlock()
				return cc, nil
			}
		}
		if !dialOnMiss {
			p.mu.Unlock()
			return nil, http2ErrNoCachedConn
		}
		http2traceGetConn(req, addr)
		call := p.getStartDialLocked(req.Context(), addr)
		p.mu.Unlock()
		<-call.done
		if http2shouldRetryDial(call, req) {
			continue
		}
		cc, err := call.res, call.err
		if err != nil {
			return nil, err
		}
		if cc.ReserveNewRequest() {
			return cc, nil
		}
	}
}

// dialCall is an in-flight Transport dial call to a host.
type http2dialCall struct {
	_ http2incomparable
	p *http2clientConnPool
	// the context associated with the request
	// that created this dialCall
	ctx  context.Context
	done chan struct{}    // closed when done
	res  *http2ClientConn // valid after done is closed
	err  error            // valid after done is closed
}

// requires p.mu is held.
func (p *http2clientConnPool) getStartDialLocked(ctx context.Context, addr string) *http2dialCall {
	if call, ok := p.dialing[addr]; ok {
		// A dial is already in-flight. Don't start another.
		return call
	}
	call := &http2dialCall{p: p, done: make(chan struct{}), ctx: ctx}
	if p.dialing == nil {
		p.dialing = make(map[string]*http2dialCall)
	}
	p.dialing[addr] = call
	go call.dial(call.ctx, addr)
	return call
}

// run in its own goroutine.
func (c *http2dialCall) dial(ctx context.Context, addr string) {
	const singleUse = false // shared conn
	c.res, c.err = c.p.t.dialClientConn(ctx, addr, singleUse)

	c.p.mu.Lock()
	delete(c.p.dialing, addr)
	if c.err == nil {
		c.p.addConnLocked(addr, c.res)
	}
	c.p.mu.Unlock()

	close(c.done)
}

// addConnIfNeeded makes a NewClientConn out of c if a connection for key doesn't
// already exist. It coalesces concurrent calls with the same key.
// This is used by the http1 Transport code when it creates a new connection. Because
// the http1 Transport doesn't de-dup TCP dials to outbound hosts (because it doesn't know
// the protocol), it can get into a situation where it has multiple TLS connections.
// This code decides which ones live or die.
// The return value used is whether c was used.
// c is never closed.
func (p *http2clientConnPool) addConnIfNeeded(key string, t *http2Transport, c *tls.Conn) (used bool, err error) {
	p.mu.Lock()
	for _, cc := range p.conns[key] {
		if cc.CanTakeNewRequest() {
			p.mu.Unlock()
			return false, nil
		}
	}
	call, dup := p.addConnCalls[key]
	if !dup {
		if p.addConnCalls == nil {
			p.addConnCalls = make(map[string]*http2addConnCall)
		}
		call = &http2addConnCall{
			p:    p,
			done: make(chan struct{}),
		}
		p.addConnCalls[key] = call
		go call.run(t, key, c)
	}
	p.mu.Unlock()

	<-call.done
	if call.err != nil {
		return false, call.err
	}
	return !dup, nil
}

type http2addConnCall struct {
	_    http2incomparable
	p    *http2clientConnPool
	done chan struct{} // closed when done
	err  error
}

func (c *http2addConnCall) run(t *http2Transport, key string, tc *tls.Conn) {
	cc, err := t.NewClientConn(tc)

	p := c.p
	p.mu.Lock()
	if err != nil {
		c.err = err
	} else {
		cc.getConnCalled = true // already called by the net/http package
		p.addConnLocked(key, cc)
	}
	delete(p.addConnCalls, key)
	p.mu.Unlock()
	close(c.done)
}

// p.mu must be held
func (p *http2clientConnPool) addConnLocked(key string, cc *http2ClientConn) {
	for _, v := range p.conns[key] {
		if v == cc {
			return
		}
	}
	if p.conns == nil {
		p.conns = make(map[string][]*http2ClientConn)
	}
	if p.keys == nil {
		p.keys = make(map[*http2ClientConn][]string)
	}
	p.conns[key] = append(p.conns[key], cc)
	p.keys[cc] = append(p.keys[cc], key)
}

func (p *http2clientConnPool) MarkDead(cc *http2ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range p.keys[cc] {
		vv, ok := p.conns[key]
		if !ok {
			continue
		}
		newList := http2filterOutClientConn(vv, cc)
		if len(newList) > 0 {
			p.conns[key] = newList
		} else {
			delete(p.conns, key)
		}
	}
	delete(p.keys, cc)
}

func (p *http2clientConnPool) closeIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// TODO: don't close a cc if it was just added to the pool
	// milliseconds ago and has never been used. There's currently
	// a small race window with the HTTP/1 Transport's integration
	// where it can add an idle conn just before using it, and
	// somebody else can concurrently call CloseIdleConns and
	// break some caller's RoundTrip.
	for _, vv := range p.conns {
		for _, cc := range vv {
			cc.closeIfIdle()
		}
	}
}

func http2filterOutClientConn(in []*http2ClientConn, exclude *http2ClientConn) []*http2ClientConn {
	out := in[:0]
	for _, v := range in {
		if v != exclude {
			out = append(out, v)
		}
	}
	// If we filtered it out, zero out the last item to prevent
	// the GC from seeing it.
	if len(in) != len(out) {
		in[len(in)-1] = nil
	}
	return out
}

// noDialClientConnPool is an implementation of http2.ClientConnPool
// which never dials. We let the HTTP/1.1 client dial and use its TLS
// connection instead.
type http2noDialClientConnPool struct{ *http2clientConnPool }

func (p http2noDialClientConnPool) GetClientConn(req *http.Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2noDialOnMiss)
}

// shouldRetryDial reports whether the current request should
// retry dialing after the call finished unsuccessfully, for example
// if the dial was canceled because of a context cancellation or
// deadline expiry.
func http2shouldRetryDial(call *http2dialCall, req *http.Request) bool {
	if call.err == nil {
		// No error, no need to retry
		return false
	}
	if call.ctx == req.Context() {
		// If the call has the same context as the request, the dial
		// should not be retried, since any cancellation will have come
		// from this request.
		return false
	}
	if !errors.Is(call.err, context.Canceled) && !errors.Is(call.err, context.DeadlineExceeded) {
		// If the call error is not because of a context cancellation or a deadline expiry,
		// the dial should not be retried.
		return false
	}
	// Only retry if the error is a context cancellation error or deadline expiry
	// and the context associated with the call was canceled or expired.
	return call.ctx.Err() != nil
}

// Buffer chunks are allocated from a pool to reduce pressure on GC.
// The maximum wasted space per dataBuffer is 2x the largest size class,
// which happens when the dataBuffer has multiple chunks and there is
// one unread byte in both the first and last chunks. We use a few size
// classes to minimize overheads for servers that typically receive very
// small request bodies.
//
// TODO: Benchmark to determine if the pools are necessary. The GC may have
// improved enough that we can instead allocate chunks like this:
// make([]byte, max(16<<10, expectedBytesRemaining))
var (
	http2dataChunkSizeClasses = []int{
		1 << 10,
		2 << 10,
		4 << 10,
		8 << 10,
		16 << 10,
	}
	http2dataChunkPools = [...]sync.Pool{
		{New: func() interface{} { return make([]byte, 1<<10) }},
		{New: func() interface{} { return make([]byte, 2<<10) }},
		{New: func() interface{} { return make([]byte, 4<<10) }},
		{New: func() interface{} { return make([]byte, 8<<10) }},
		{New: func() interface{} { return make([]byte, 16<<10) }},
	}
)

func http2getDataBufferChunk(size int64) []byte {
	i := 0
	for ; i < len(http2dataChunkSizeClasses)-1; i++ {
		if size <= int64(http2dataChunkSizeClasses[i]) {
			break
		}
	}
	return http2dataChunkPools[i].Get().([]byte)
}

func http2putDataBufferChunk(p []byte) {
	for i, n := range http2dataChunkSizeClasses {
		if len(p) == n {
			http2dataChunkPools[i].Put(p)
			return
		}
	}
	panic(fmt.Sprintf("unexpected buffer len=%v", len(p)))
}

// dataBuffer is an io.ReadWriter backed by a list of data chunks.
// Each dataBuffer is used to read DATA frames on a single stream.
// The buffer is divided into chunks so the server can limit the
// total memory used by a single connection without limiting the
// request body size on any single stream.
type http2dataBuffer struct {
	chunks   [][]byte
	r        int   // next byte to read is chunks[0][r]
	w        int   // next byte to write is chunks[len(chunks)-1][w]
	size     int   // total buffered bytes
	expected int64 // we expect at least this many bytes in future Write calls (ignored if <= 0)
}

var http2errReadEmpty = errors.New("read from empty dataBuffer")

// Read copies bytes from the buffer into p.
// It is an error to read when no data is available.
func (b *http2dataBuffer) Read(p []byte) (int, error) {
	if b.size == 0 {
		return 0, http2errReadEmpty
	}
	var ntotal int
	for len(p) > 0 && b.size > 0 {
		readFrom := b.bytesFromFirstChunk()
		n := copy(p, readFrom)
		p = p[n:]
		ntotal += n
		b.r += n
		b.size -= n
		// If the first chunk has been consumed, advance to the next chunk.
		if b.r == len(b.chunks[0]) {
			http2putDataBufferChunk(b.chunks[0])
			end := len(b.chunks) - 1
			copy(b.chunks[:end], b.chunks[1:])
			b.chunks[end] = nil
			b.chunks = b.chunks[:end]
			b.r = 0
		}
	}
	return ntotal, nil
}

func (b *http2dataBuffer) bytesFromFirstChunk() []byte {
	if len(b.chunks) == 1 {
		return b.chunks[0][b.r:b.w]
	}
	return b.chunks[0][b.r:]
}

// Len returns the number of bytes of the unread portion of the buffer.
func (b *http2dataBuffer) Len() int {
	return b.size
}

// Write appends p to the buffer.
func (b *http2dataBuffer) Write(p []byte) (int, error) {
	ntotal := len(p)
	for len(p) > 0 {
		// If the last chunk is empty, allocate a new chunk. Try to allocate
		// enough to fully copy p plus any additional bytes we expect to
		// receive. However, this may allocate less than len(p).
		want := int64(len(p))
		if b.expected > want {
			want = b.expected
		}
		chunk := b.lastChunkOrAlloc(want)
		n := copy(chunk[b.w:], p)
		p = p[n:]
		b.w += n
		b.size += n
		b.expected -= int64(n)
	}
	return ntotal, nil
}

func (b *http2dataBuffer) lastChunkOrAlloc(want int64) []byte {
	if len(b.chunks) != 0 {
		last := b.chunks[len(b.chunks)-1]
		if b.w < len(last) {
			return last
		}
	}
	chunk := http2getDataBufferChunk(want)
	b.chunks = append(b.chunks, chunk)
	b.w = 0
	return chunk
}

// An ErrCode is an unsigned 32-bit error code as defined in the HTTP/2 spec.
type http2ErrCode uint32

const (
	http2ErrCodeNo                 http2ErrCode = 0x0
	http2ErrCodeProtocol           http2ErrCode = 0x1
	http2ErrCodeInternal           http2ErrCode = 0x2
	http2ErrCodeFlowControl        http2ErrCode = 0x3
	http2ErrCodeSettingsTimeout    http2ErrCode = 0x4
	http2ErrCodeStreamClosed       http2ErrCode = 0x5
	http2ErrCodeFrameSize          http2ErrCode = 0x6
	http2ErrCodeRefusedStream      http2ErrCode = 0x7
	http2ErrCodeCancel             http2ErrCode = 0x8
	http2ErrCodeCompression        http2ErrCode = 0x9
	http2ErrCodeConnect            http2ErrCode = 0xa
	http2ErrCodeEnhanceYourCalm    http2ErrCode = 0xb
	http2ErrCodeInadequateSecurity http2ErrCode = 0xc
	http2ErrCodeHTTP11Required     http2ErrCode = 0xd
)

var http2errCodeName = map[http2ErrCode]string{
	http2ErrCodeNo:                 "NO_ERROR",
	http2ErrCodeProtocol:           "PROTOCOL_ERROR",
	http2ErrCodeInternal:           "INTERNAL_ERROR",
	http2ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
	http2ErrCodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	http2ErrCodeStreamClosed:       "STREAM_CLOSED",
	http2ErrCodeFrameSize:          "FRAME_SIZE_ERROR",
	http2ErrCodeRefusedStream:      "REFUSED_STREAM",
	http2ErrCodeCancel:             "CANCEL",
	http2ErrCodeCompression:        "COMPRESSION_ERROR",
	http2ErrCodeConnect:            "CONNECT_ERROR",
	http2ErrCodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	http2ErrCodeInadequateSecurity: "INADEQUATE_SECURITY",
	http2ErrCodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

func (e http2ErrCode) String() string {
	if s, ok := http2errCodeName[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown error code 0x%x", uint32(e))
}

func (e http2ErrCode) stringToken() string {
	if s, ok := http2errCodeName[e]; ok {
		return s
	}
	return fmt.Sprintf("ERR_UNKNOWN_%d", uint32(e))
}

// ConnectionError is an error that results in the termination of the
// entire connection.
type http2ConnectionError http2ErrCode

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %s", http2ErrCode(e))
}

// StreamError is an error that only affects one stream within an
// HTTP/2 connection.
type http2StreamError struct {
	StreamID uint32
	Code     http2ErrCode
	Cause    error // optional additional detail
}

// errFromPeer is a sentinel error value for StreamError.Cause to
// indicate that the StreamError was sent from the peer over the wire
// and wasn't locally generated in the Transport.
var http2errFromPeer = errors.New("received from peer")

func http2streamError(id uint32, code http2ErrCode) http2StreamError {
	return http2StreamError{StreamID: id, Code: code}
}

func (e http2StreamError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("stream error: stream ID %d; %v; %v", e.StreamID, e.Code, e.Cause)
	}
	return fmt.Sprintf("stream error: stream ID %d; %v", e.StreamID, e.Code)
}

// 6.9.1 The Flow Control Window
// "If a sender receives a WINDOW_UPDATE that causes a flow control
// window to exceed this maximum it MUST terminate either the stream
// or the connection, as appropriate. For streams, [...]; for the
// connection, a GOAWAY frame with a FLOW_CONTROL_ERROR code."
type http2goAwayFlowError struct{}

func (http2goAwayFlowError) Error() string { return "connection exceeded flow control window size" }

// connError represents an HTTP/2 ConnectionError error code, along
// with a string (for debugging) explaining why.
//
// Errors of this type are only returned by the frame parser functions
// and converted into ConnectionError(Code), after stashing away
// the Reason into the Framer's errDetail field, accessible via
// the (*Framer).ErrorDetail method.
type http2connError struct {
	Code   http2ErrCode // the ConnectionError error code
	Reason string       // additional reason
}

func (e http2connError) Error() string {
	return fmt.Sprintf("http2: connection error: %v: %v", e.Code, e.Reason)
}

type http2pseudoHeaderError string

func (e http2pseudoHeaderError) Error() string {
	return fmt.Sprintf("invalid pseudo-header %q", string(e))
}

type http2duplicatePseudoHeaderError string

func (e http2duplicatePseudoHeaderError) Error() string {
	return fmt.Sprintf("duplicate pseudo-header %q", string(e))
}

type http2headerFieldNameError string

func (e http2headerFieldNameError) Error() string {
	return fmt.Sprintf("invalid header field name %q", string(e))
}

type http2headerFieldValueError string

func (e http2headerFieldValueError) Error() string {
	return fmt.Sprintf("invalid header field value for %q", string(e))
}

var (
	http2errMixPseudoHeaderTypes = errors.New("mix of request and response pseudo headers")
	http2errPseudoAfterRegular   = errors.New("pseudo header field after regular")
)

// inflowMinRefresh is the minimum number of bytes we'll send for a
// flow control window update.
const http2inflowMinRefresh = 4 << 10

// inflow accounts for an inbound flow control window.
// It tracks both the latest window sent to the peer (used for enforcement)
// and the accumulated unsent window.
type http2inflow struct {
	avail  int32
	unsent int32
}

// init sets the initial window.
func (f *http2inflow) init(n int32) {
	f.avail = n
}

// add adds n bytes to the window, with a maximum window size of max,
// indicating that the peer can now send us more data.
// For example, the user read from a {Request,Response} body and consumed
// some of the buffered data, so the peer can now send more.
// It returns the number of bytes to send in a WINDOW_UPDATE frame to the peer.
// Window updates are accumulated and sent when the unsent capacity
// is at least inflowMinRefresh or will at least double the peer's available window.
func (f *http2inflow) add(n int) (connAdd int32) {
	if n < 0 {
		panic("negative update")
	}
	unsent := int64(f.unsent) + int64(n)
	// "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets."
	// RFC 7540 Section 6.9.1.
	const maxWindow = 1<<31 - 1
	if unsent+int64(f.avail) > maxWindow {
		panic("flow control update exceeds maximum window size")
	}
	f.unsent = int32(unsent)
	if f.unsent < http2inflowMinRefresh && f.unsent < f.avail {
		// If there aren't at least inflowMinRefresh bytes of window to send,
		// and this update won't at least double the window, buffer the update for later.
		return 0
	}
	f.avail += f.unsent
	f.unsent = 0
	return int32(unsent)
}

// take attempts to take n bytes from the peer's flow control window.
// It reports whether the window has available capacity.
func (f *http2inflow) take(n uint32) bool {
	if n > uint32(f.avail) {
		return false
	}
	f.avail -= int32(n)
	return true
}

// takeInflows attempts to take n bytes from two inflows,
// typically connection-level and stream-level flows.
// It reports whether both windows have available capacity.
func http2takeInflows(f1, f2 *http2inflow, n uint32) bool {
	if n > uint32(f1.avail) || n > uint32(f2.avail) {
		return false
	}
	f1.avail -= int32(n)
	f2.avail -= int32(n)
	return true
}

// outflow is the outbound flow control window's size.
type http2outflow struct {
	_ http2incomparable

	// n is the number of DATA bytes we're allowed to send.
	// An outflow is kept both on a conn and a per-stream.
	n int32

	// conn points to the shared connection-level outflow that is
	// shared by all streams on that conn. It is nil for the outflow
	// that's on the conn directly.
	conn *http2outflow
}

func (f *http2outflow) setConnFlow(cf *http2outflow) { f.conn = cf }

func (f *http2outflow) available() int32 {
	n := f.n
	if f.conn != nil && f.conn.n < n {
		n = f.conn.n
	}
	return n
}

func (f *http2outflow) take(n int32) {
	if n > f.available() {
		panic("internal error: took too much")
	}
	f.n -= n
	if f.conn != nil {
		f.conn.n -= n
	}
}

// add adds n bytes (positive or negative) to the flow control window.
// It returns false if the sum would exceed 2^31-1.
func (f *http2outflow) add(n int32) bool {
	sum := f.n + n
	if (sum > n) == (f.n > 0) {
		f.n = sum
		return true
	}
	return false
}

const http2frameHeaderLen = 9

var http2padZeros = make([]byte, 255) // zeros for padding

// A FrameType is a registered frame type as defined in
// https://httpwg.org/specs/rfc7540.html#rfc.section.11.2
type http2FrameType uint8

const (
	http2FrameData         http2FrameType = 0x0
	http2FrameHeaders      http2FrameType = 0x1
	http2FramePriority     http2FrameType = 0x2
	http2FrameRSTStream    http2FrameType = 0x3
	http2FrameSettings     http2FrameType = 0x4
	http2FramePushPromise  http2FrameType = 0x5
	http2FramePing         http2FrameType = 0x6
	http2FrameGoAway       http2FrameType = 0x7
	http2FrameWindowUpdate http2FrameType = 0x8
	http2FrameContinuation http2FrameType = 0x9
)

var http2frameName = map[http2FrameType]string{
	http2FrameData:         "DATA",
	http2FrameHeaders:      "HEADERS",
	http2FramePriority:     "PRIORITY",
	http2FrameRSTStream:    "RST_STREAM",
	http2FrameSettings:     "SETTINGS",
	http2FramePushPromise:  "PUSH_PROMISE",
	http2FramePing:         "PING",
	http2FrameGoAway:       "GOAWAY",
	http2FrameWindowUpdate: "WINDOW_UPDATE",
	http2FrameContinuation: "CONTINUATION",
}

func (t http2FrameType) String() string {
	if s, ok := http2frameName[t]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN_FRAME_TYPE_%d", uint8(t))
}

// Flags is a bitmask of HTTP/2 flags.
// The meaning of flags varies depending on the frame type.
type http2Flags uint8

// Has reports whether f contains all (0 or more) flags in v.
func (f http2Flags) Has(v http2Flags) bool {
	return (f & v) == v
}

// Frame-specific FrameHeader flag bits.
const (
	// Data Frame
	http2FlagDataEndStream http2Flags = 0x1
	http2FlagDataPadded    http2Flags = 0x8

	// Headers Frame
	http2FlagHeadersEndStream  http2Flags = 0x1
	http2FlagHeadersEndHeaders http2Flags = 0x4
	http2FlagHeadersPadded     http2Flags = 0x8
	http2FlagHeadersPriority   http2Flags = 0x20

	// Settings Frame
	http2FlagSettingsAck http2Flags = 0x1

	// Ping Frame
	http2FlagPingAck http2Flags = 0x1

	// Continuation Frame
	http2FlagContinuationEndHeaders http2Flags = 0x4

	http2FlagPushPromiseEndHeaders http2Flags = 0x4
	http2FlagPushPromisePadded     http2Flags = 0x8
)

var http2flagName = map[http2FrameType]map[http2Flags]string{
	http2FrameData: {
		http2FlagDataEndStream: "END_STREAM",
		http2FlagDataPadded:    "PADDED",
	},
	http2FrameHeaders: {
		http2FlagHeadersEndStream:  "END_STREAM",
		http2FlagHeadersEndHeaders: "END_HEADERS",
		http2FlagHeadersPadded:     "PADDED",
		http2FlagHeadersPriority:   "PRIORITY",
	},
	http2FrameSettings: {
		http2FlagSettingsAck: "ACK",
	},
	http2FramePing: {
		http2FlagPingAck: "ACK",
	},
	http2FrameContinuation: {
		http2FlagContinuationEndHeaders: "END_HEADERS",
	},
	http2FramePushPromise: {
		http2FlagPushPromiseEndHeaders: "END_HEADERS",
		http2FlagPushPromisePadded:     "PADDED",
	},
}

// a frameParser parses a frame given its FrameHeader and payload
// bytes. The length of payload will always equal fh.Length (which
// might be 0).
type http2frameParser func(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error)

var http2frameParsers = map[http2FrameType]http2frameParser{
	http2FrameData:         http2parseDataFrame,
	http2FrameHeaders:      http2parseHeadersFrame,
	http2FramePriority:     http2parsePriorityFrame,
	http2FrameRSTStream:    http2parseRSTStreamFrame,
	http2FrameSettings:     http2parseSettingsFrame,
	http2FramePushPromise:  http2parsePushPromise,
	http2FramePing:         http2parsePingFrame,
	http2FrameGoAway:       http2parseGoAwayFrame,
	http2FrameWindowUpdate: http2parseWindowUpdateFrame,
	http2FrameContinuation: http2parseContinuationFrame,
}

func http2typeFrameParser(t http2FrameType) http2frameParser {
	if f := http2frameParsers[t]; f != nil {
		return f
	}
	return http2parseUnknownFrame
}

// A FrameHeader is the 9 byte header of all HTTP/2 frames.
//
// See https://httpwg.org/specs/rfc7540.html#FrameHeader
type http2FrameHeader struct {
	valid bool // caller can access []byte fields in the Frame

	// Type is the 1 byte frame type. There are ten standard frame
	// types, but extension frame types may be written by WriteRawFrame
	// and will be returned by ReadFrame (as UnknownFrame).
	Type http2FrameType

	// Flags are the 1 byte of 8 potential bit flags per frame.
	// They are specific to the frame type.
	Flags http2Flags

	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// StreamID is which stream this frame is for. Certain frames
	// are not stream-specific, in which case this field is 0.
	StreamID uint32
}

// Header returns h. It exists so FrameHeaders can be embedded in other
// specific frame types and implement the Frame interface.
func (h http2FrameHeader) Header() http2FrameHeader { return h }

func (h http2FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	h.writeDebug(&buf)
	buf.WriteByte(']')
	return buf.String()
}

func (h http2FrameHeader) writeDebug(buf *bytes.Buffer) {
	buf.WriteString(h.Type.String())
	if h.Flags != 0 {
		buf.WriteString(" flags=")
		set := 0
		for i := uint8(0); i < 8; i++ {
			if h.Flags&(1<<i) == 0 {
				continue
			}
			set++
			if set > 1 {
				buf.WriteByte('|')
			}
			name := http2flagName[h.Type][http2Flags(1<<i)]
			if name != "" {
				buf.WriteString(name)
			} else {
				fmt.Fprintf(buf, "0x%x", 1<<i)
			}
		}
	}
	if h.StreamID != 0 {
		fmt.Fprintf(buf, " stream=%d", h.StreamID)
	}
	fmt.Fprintf(buf, " len=%d", h.Length)
}

func (h *http2FrameHeader) checkValid() {
	if !h.valid {
		panic("Frame accessor called on non-owned Frame")
	}
}

func (h *http2FrameHeader) invalidate() { h.valid = false }

// frame header bytes.
// Used only by ReadFrameHeader.
var http2fhBytes = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, http2frameHeaderLen)
		return &buf
	},
}

// ReadFrameHeader reads 9 bytes from r and returns a FrameHeader.
// Most users should use Framer.ReadFrame instead.
func http2ReadFrameHeader(r io.Reader) (http2FrameHeader, error) {
	bufp := http2fhBytes.Get().(*[]byte)
	defer http2fhBytes.Put(bufp)
	return http2readFrameHeader(*bufp, r)
}

func http2readFrameHeader(buf []byte, r io.Reader) (http2FrameHeader, error) {
	_, err := io.ReadFull(r, buf[:http2frameHeaderLen])
	if err != nil {
		return http2FrameHeader{}, err
	}
	return http2FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    http2Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
		valid:    true,
	}, nil
}

// A Frame is the base interface implemented by all frame types.
// Callers will generally type-assert the specific frame type:
// *HeadersFrame, *SettingsFrame, *WindowUpdateFrame, etc.
//
// Frames are only valid until the next call to Framer.ReadFrame.
type http2Frame interface {
	Header() http2FrameHeader

	// invalidate is called by Framer.ReadFrame to make this
	// frame's buffers as being invalid, since the subsequent
	// frame will reuse them.
	invalidate()
}

// A Framer reads and writes Frames.
type http2Framer struct {
	r         io.Reader
	lastFrame http2Frame
	errDetail error

	// countError is a non-nil func that's called on a frame parse
	// error with some unique error path token. It's initialized
	// from Transport.CountError or Server.CountError.
	countError func(errToken string)

	// lastHeaderStream is non-zero if the last frame was an
	// unfinished HEADERS/CONTINUATION.
	lastHeaderStream uint32

	maxReadSize uint32
	headerBuf   [http2frameHeaderLen]byte

	// TODO: let getReadBuf be configurable, and use a less memory-pinning
	// allocator in server.go to minimize memory pinned for many idle conns.
	// Will probably also need to make frame invalidation have a hook too.
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf

	maxWriteSize uint32 // zero means unlimited; TODO: implement

	w    io.Writer
	wbuf []byte

	// AllowIllegalWrites permits the Framer's Write methods to
	// write frames that do not conform to the HTTP/2 spec. This
	// permits using the Framer to test other HTTP/2
	// implementations' conformance to the spec.
	// If false, the Write methods will prefer to return an error
	// rather than comply.
	AllowIllegalWrites bool

	// AllowIllegalReads permits the Framer's ReadFrame method
	// to return non-compliant frames or frame orders.
	// This is for testing and permits using the Framer to test
	// other HTTP/2 implementations' conformance to the spec.
	// It is not compatible with ReadMetaHeaders.
	AllowIllegalReads bool

	// ReadMetaHeaders if non-nil causes ReadFrame to merge
	// HEADERS and CONTINUATION frames together and return
	// MetaHeadersFrame instead.
	ReadMetaHeaders *hpack.Decoder

	// MaxHeaderListSize is the http2 MAX_HEADER_LIST_SIZE.
	// It's used only if ReadMetaHeaders is set; 0 means a sane default
	// (currently 16MB)
	// If the limit is hit, MetaHeadersFrame.Truncated is set true.
	MaxHeaderListSize uint32

	// TODO: track which type of frame & with which flags was sent
	// last. Then return an error (unless AllowIllegalWrites) if
	// we're in the middle of a header block and a
	// non-Continuation or Continuation on a different stream is
	// attempted to be written.

	logReads, logWrites bool

	debugFramer       *http2Framer // only use for logging written writes
	debugFramerBuf    *bytes.Buffer
	debugReadLoggerf  func(string, ...interface{})
	debugWriteLoggerf func(string, ...interface{})

	frameCache *http2frameCache // nil if frames aren't reused (default)
}

func (fr *http2Framer) maxHeaderListSize() uint32 {
	if fr.MaxHeaderListSize == 0 {
		return 16 << 20 // sane default, per docs
	}
	return fr.MaxHeaderListSize
}

func (f *http2Framer) startWrite(ftype http2FrameType, flags http2Flags, streamID uint32) {
	// Write the FrameHeader.
	f.wbuf = append(f.wbuf[:0],
		0, // 3 bytes of length, filled in in endWrite
		0,
		0,
		byte(ftype),
		byte(flags),
		byte(streamID>>24),
		byte(streamID>>16),
		byte(streamID>>8),
		byte(streamID))
}

func (f *http2Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(f.wbuf) - http2frameHeaderLen
	if length >= (1 << 24) {
		return http2ErrFrameTooLarge
	}
	_ = append(f.wbuf[:0],
		byte(length>>16),
		byte(length>>8),
		byte(length))
	if f.logWrites {
		f.logWrite()
	}

	n, err := f.w.Write(f.wbuf)
	if err == nil && n != len(f.wbuf) {
		err = io.ErrShortWrite
	}
	return err
}

func (f *http2Framer) logWrite() {
	if f.debugFramer == nil {
		f.debugFramerBuf = new(bytes.Buffer)
		f.debugFramer = http2NewFramer(nil, f.debugFramerBuf)
		f.debugFramer.logReads = false // we log it ourselves, saying "wrote" below
		// Let us read anything, even if we accidentally wrote it
		// in the wrong order:
		f.debugFramer.AllowIllegalReads = true
	}
	f.debugFramerBuf.Write(f.wbuf)
	fr, err := f.debugFramer.ReadFrame()
	if err != nil {
		f.debugWriteLoggerf("http2: Framer %p: failed to decode just-written frame", f)
		return
	}
	f.debugWriteLoggerf("http2: Framer %p: wrote %v", f, http2summarizeFrame(fr))
}

func (f *http2Framer) writeByte(v byte) { f.wbuf = append(f.wbuf, v) }

func (f *http2Framer) writeBytes(v []byte) { f.wbuf = append(f.wbuf, v...) }

func (f *http2Framer) writeUint16(v uint16) { f.wbuf = append(f.wbuf, byte(v>>8), byte(v)) }

func (f *http2Framer) writeUint32(v uint32) {
	f.wbuf = append(f.wbuf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

const (
	http2minMaxFrameSize = 1 << 14
	http2maxFrameSize    = 1<<24 - 1
)

// SetReuseFrames allows the Framer to reuse Frames.
// If called on a Framer, Frames returned by calls to ReadFrame are only
// valid until the next call to ReadFrame.
func (fr *http2Framer) SetReuseFrames() {
	if fr.frameCache != nil {
		return
	}
	fr.frameCache = &http2frameCache{}
}

type http2frameCache struct {
	dataFrame http2DataFrame
}

func (fc *http2frameCache) getDataFrame() *http2DataFrame {
	if fc == nil {
		return &http2DataFrame{}
	}
	return &fc.dataFrame
}

// NewFramer returns a Framer that writes frames to w and reads them from r.
func http2NewFramer(w io.Writer, r io.Reader) *http2Framer {
	fr := &http2Framer{
		w:                 w,
		r:                 r,
		countError:        func(string) {},
		logReads:          http2logFrameReads,
		logWrites:         http2logFrameWrites,
		debugReadLoggerf:  log.Printf,
		debugWriteLoggerf: log.Printf,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	fr.SetMaxReadFrameSize(http2maxFrameSize)
	return fr
}

// SetMaxReadFrameSize sets the maximum size of a frame
// that will be read by a subsequent call to ReadFrame.
// It is the caller's responsibility to advertise this
// limit with a SETTINGS frame.
func (fr *http2Framer) SetMaxReadFrameSize(v uint32) {
	if v > http2maxFrameSize {
		v = http2maxFrameSize
	}
	fr.maxReadSize = v
}

// ErrorDetail returns a more detailed error of the last error
// returned by Framer.ReadFrame. For instance, if ReadFrame
// returns a StreamError with code PROTOCOL_ERROR, ErrorDetail
// will say exactly what was invalid. ErrorDetail is not guaranteed
// to return a non-nil value and like the rest of the http2 package,
// its return value is not protected by an API compatibility promise.
// ErrorDetail is reset after the next call to ReadFrame.
func (fr *http2Framer) ErrorDetail() error {
	return fr.errDetail
}

// ErrFrameTooLarge is returned from Framer.ReadFrame when the peer
// sends a frame that is larger than declared with SetMaxReadFrameSize.
var http2ErrFrameTooLarge = errors.New("http2: frame too large")

// terminalReadFrameError reports whether err is an unrecoverable
// error from ReadFrame and no other frames should be read.
func http2terminalReadFrameError(err error) bool {
	if _, ok := err.(http2StreamError); ok {
		return false
	}
	return err != nil
}

// ReadFrame reads a single frame. The returned Frame is only valid
// until the next call to ReadFrame.
//
// If the frame is larger than previously set with SetMaxReadFrameSize, the
// returned error is ErrFrameTooLarge. Other errors may be of type
// ConnectionError, StreamError, or anything else from the underlying
// reader.
func (fr *http2Framer) ReadFrame() (http2Frame, error) {
	fr.errDetail = nil
	if fr.lastFrame != nil {
		fr.lastFrame.invalidate()
	}
	fh, err := http2readFrameHeader(fr.headerBuf[:], fr.r)
	if err != nil {
		return nil, err
	}
	if fh.Length > fr.maxReadSize {
		return nil, http2ErrFrameTooLarge
	}
	payload := fr.getReadBuf(fh.Length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return nil, err
	}
	f, err := http2typeFrameParser(fh.Type)(fr.frameCache, fh, fr.countError, payload)
	if err != nil {
		if ce, ok := err.(http2connError); ok {
			return nil, fr.connError(ce.Code, ce.Reason)
		}
		return nil, err
	}
	if err := fr.checkFrameOrder(f); err != nil {
		return nil, err
	}
	if fr.logReads {
		fr.debugReadLoggerf("http2: Framer %p: read %v", fr, http2summarizeFrame(f))
	}
	if fh.Type == http2FrameHeaders && fr.ReadMetaHeaders != nil {
		return fr.readMetaFrame(f.(*http2HeadersFrame))
	}
	return f, nil
}

// connError returns ConnectionError(code) but first
// stashes away a public reason to the caller can optionally relay it
// to the peer before hanging up on them. This might help others debug
// their implementations.
func (fr *http2Framer) connError(code http2ErrCode, reason string) error {
	fr.errDetail = errors.New(reason)
	return http2ConnectionError(code)
}

// checkFrameOrder reports an error if f is an invalid frame to return
// next from ReadFrame. Mostly it checks whether HEADERS and
// CONTINUATION frames are contiguous.
func (fr *http2Framer) checkFrameOrder(f http2Frame) error {
	last := fr.lastFrame
	fr.lastFrame = f
	if fr.AllowIllegalReads {
		return nil
	}

	fh := f.Header()
	if fr.lastHeaderStream != 0 {
		if fh.Type != http2FrameContinuation {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got %s for stream %d; expected CONTINUATION following %s for stream %d",
					fh.Type, fh.StreamID,
					last.Header().Type, fr.lastHeaderStream))
		}
		if fh.StreamID != fr.lastHeaderStream {
			return fr.connError(http2ErrCodeProtocol,
				fmt.Sprintf("got CONTINUATION for stream %d; expected stream %d",
					fh.StreamID, fr.lastHeaderStream))
		}
	} else if fh.Type == http2FrameContinuation {
		return fr.connError(http2ErrCodeProtocol, fmt.Sprintf("unexpected CONTINUATION for stream %d", fh.StreamID))
	}

	switch fh.Type {
	case http2FrameHeaders, http2FrameContinuation:
		if fh.Flags.Has(http2FlagHeadersEndHeaders) {
			fr.lastHeaderStream = 0
		} else {
			fr.lastHeaderStream = fh.StreamID
		}
	}

	return nil
}

// A DataFrame conveys arbitrary, variable-length sequences of octets
// associated with a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.1
type http2DataFrame struct {
	http2FrameHeader
	data []byte
}

func (f *http2DataFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagDataEndStream)
}

// Data returns the frame's data octets, not including any padding
// size byte or padding suffix bytes.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2DataFrame) Data() []byte {
	f.checkValid()
	return f.data
}

func http2parseDataFrame(fc *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		// DATA frames MUST be associated with a stream. If a
		// DATA frame is received whose stream identifier
		// field is 0x0, the recipient MUST respond with a
		// connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_data_stream_0")
		return nil, http2connError{http2ErrCodeProtocol, "DATA frame with stream ID 0"}
	}
	f := fc.getDataFrame()
	f.http2FrameHeader = fh

	var padSize byte
	if fh.Flags.Has(http2FlagDataPadded) {
		var err error
		payload, padSize, err = http2readByte(payload)
		if err != nil {
			countError("frame_data_pad_byte_short")
			return nil, err
		}
	}
	if int(padSize) > len(payload) {
		// If the length of the padding is greater than the
		// length of the frame payload, the recipient MUST
		// treat this as a connection error.
		// Filed: https://github.com/http2/http2-spec/issues/610
		countError("frame_data_pad_too_big")
		return nil, http2connError{http2ErrCodeProtocol, "pad size larger than data payload"}
	}
	f.data = payload[:len(payload)-int(padSize)]
	return f, nil
}

var (
	http2errStreamID    = errors.New("invalid stream ID")
	http2errDepStreamID = errors.New("invalid dependent stream ID")
	http2errPadLength   = errors.New("pad length too large")
	http2errPadBytes    = errors.New("padding bytes must all be zeros unless AllowIllegalWrites is enabled")
)

func http2validStreamIDOrZero(streamID uint32) bool {
	return streamID&(1<<31) == 0
}

func http2validStreamID(streamID uint32) bool {
	return streamID != 0 && streamID&(1<<31) == 0
}

// WriteData writes a DATA frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteData(streamID uint32, endStream bool, data []byte) error {
	return f.WriteDataPadded(streamID, endStream, data, nil)
}

// WriteDataPadded writes a DATA frame with optional padding.
//
// If pad is nil, the padding bit is not sent.
// The length of pad must not exceed 255 bytes.
// The bytes of pad must all be zero, unless f.AllowIllegalWrites is set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility not to violate the maximum frame size
// and to not call other Write methods concurrently.
func (f *http2Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if err := f.startWriteDataPadded(streamID, endStream, data, pad); err != nil {
		return err
	}
	return f.endWrite()
}

// startWriteDataPadded is WriteDataPadded, but only writes the frame to the Framer's internal buffer.
// The caller should call endWrite to flush the frame to the underlying writer.
func (f *http2Framer) startWriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	if len(pad) > 0 {
		if len(pad) > 255 {
			return http2errPadLength
		}
		if !f.AllowIllegalWrites {
			for _, b := range pad {
				if b != 0 {
					// "Padding octets MUST be set to zero when sending."
					return http2errPadBytes
				}
			}
		}
	}
	var flags http2Flags
	if endStream {
		flags |= http2FlagDataEndStream
	}
	if pad != nil {
		flags |= http2FlagDataPadded
	}
	f.startWrite(http2FrameData, flags, streamID)
	if pad != nil {
		f.wbuf = append(f.wbuf, byte(len(pad)))
	}
	f.wbuf = append(f.wbuf, data...)
	f.wbuf = append(f.wbuf, pad...)
	return nil
}

// A SettingsFrame conveys configuration parameters that affect how
// endpoints communicate, such as preferences and constraints on peer
// behavior.
//
// See https://httpwg.org/specs/rfc7540.html#SETTINGS
type http2SettingsFrame struct {
	http2FrameHeader
	p []byte
}

func http2parseSettingsFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.Flags.Has(http2FlagSettingsAck) && fh.Length > 0 {
		// When this (ACK 0x1) bit is set, the payload of the
		// SETTINGS frame MUST be empty. Receipt of a
		// SETTINGS frame with the ACK flag set and a length
		// field value other than 0 MUST be treated as a
		// connection error (Section 5.4.1) of type
		// FRAME_SIZE_ERROR.
		countError("frame_settings_ack_with_length")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		// SETTINGS frames always apply to a connection,
		// never a single stream. The stream identifier for a
		// SETTINGS frame MUST be zero (0x0).  If an endpoint
		// receives a SETTINGS frame whose stream identifier
		// field is anything other than 0x0, the endpoint MUST
		// respond with a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR.
		countError("frame_settings_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p)%6 != 0 {
		countError("frame_settings_mod_6")
		// Expecting even number of 6 byte settings.
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	f := &http2SettingsFrame{http2FrameHeader: fh, p: p}
	if v, ok := f.Value(http2SettingInitialWindowSize); ok && v > (1<<31)-1 {
		countError("frame_settings_window_size_too_big")
		// Values above the maximum flow control window size of 2^31 - 1 MUST
		// be treated as a connection error (Section 5.4.1) of type
		// FLOW_CONTROL_ERROR.
		return nil, http2ConnectionError(http2ErrCodeFlowControl)
	}
	return f, nil
}

func (f *http2SettingsFrame) IsAck() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagSettingsAck)
}

func (f *http2SettingsFrame) Value(id http2SettingID) (v uint32, ok bool) {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if s := f.Setting(i); s.ID == id {
			return s.Val, true
		}
	}
	return 0, false
}

// Setting returns the setting from the frame at the given 0-based index.
// The index must be >= 0 and less than f.NumSettings().
func (f *http2SettingsFrame) Setting(i int) http2Setting {
	buf := f.p
	return http2Setting{
		ID:  http2SettingID(binary.BigEndian.Uint16(buf[i*6 : i*6+2])),
		Val: binary.BigEndian.Uint32(buf[i*6+2 : i*6+6]),
	}
}

func (f *http2SettingsFrame) NumSettings() int { return len(f.p) / 6 }

// HasDuplicates reports whether f contains any duplicate setting IDs.
func (f *http2SettingsFrame) HasDuplicates() bool {
	num := f.NumSettings()
	if num == 0 {
		return false
	}
	// If it's small enough (the common case), just do the n^2
	// thing and avoid a map allocation.
	if num < 10 {
		for i := 0; i < num; i++ {
			idi := f.Setting(i).ID
			for j := i + 1; j < num; j++ {
				idj := f.Setting(j).ID
				if idi == idj {
					return true
				}
			}
		}
		return false
	}
	seen := map[http2SettingID]bool{}
	for i := 0; i < num; i++ {
		id := f.Setting(i).ID
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// ForeachSetting runs fn for each setting.
// It stops and returns the first error.
func (f *http2SettingsFrame) ForeachSetting(fn func(http2Setting) error) error {
	f.checkValid()
	for i := 0; i < f.NumSettings(); i++ {
		if err := fn(f.Setting(i)); err != nil {
			return err
		}
	}
	return nil
}

// WriteSettings writes a SETTINGS frame with zero or more settings
// specified and the ACK bit not set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettings(settings ...http2Setting) error {
	f.startWrite(http2FrameSettings, 0, 0)
	for _, s := range settings {
		f.writeUint16(uint16(s.ID))
		f.writeUint32(s.Val)
	}
	return f.endWrite()
}

// WriteSettingsAck writes an empty SETTINGS frame with the ACK bit set.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteSettingsAck() error {
	f.startWrite(http2FrameSettings, http2FlagSettingsAck, 0)
	return f.endWrite()
}

// A PingFrame is a mechanism for measuring a minimal round trip time
// from the sender, as well as determining whether an idle connection
// is still functional.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.7
type http2PingFrame struct {
	http2FrameHeader
	Data [8]byte
}

func (f *http2PingFrame) IsAck() bool { return f.Flags.Has(http2FlagPingAck) }

func http2parsePingFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if len(payload) != 8 {
		countError("frame_ping_length")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID != 0 {
		countError("frame_ping_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	f := &http2PingFrame{http2FrameHeader: fh}
	copy(f.Data[:], payload)
	return f, nil
}

func (f *http2Framer) WritePing(ack bool, data [8]byte) error {
	var flags http2Flags
	if ack {
		flags = http2FlagPingAck
	}
	f.startWrite(http2FramePing, flags, 0)
	f.writeBytes(data[:])
	return f.endWrite()
}

// A GoAwayFrame informs the remote peer to stop creating streams on this connection.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.8
type http2GoAwayFrame struct {
	http2FrameHeader
	LastStreamID uint32
	ErrCode      http2ErrCode
	debugData    []byte
}

// DebugData returns any debug data in the GOAWAY frame. Its contents
// are not defined.
// The caller must not retain the returned memory past the next
// call to ReadFrame.
func (f *http2GoAwayFrame) DebugData() []byte {
	f.checkValid()
	return f.debugData
}

func http2parseGoAwayFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID != 0 {
		countError("frame_goaway_has_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(p) < 8 {
		countError("frame_goaway_short")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	return &http2GoAwayFrame{
		http2FrameHeader: fh,
		LastStreamID:     binary.BigEndian.Uint32(p[:4]) & (1<<31 - 1),
		ErrCode:          http2ErrCode(binary.BigEndian.Uint32(p[4:8])),
		debugData:        p[8:],
	}, nil
}

func (f *http2Framer) WriteGoAway(maxStreamID uint32, code http2ErrCode, debugData []byte) error {
	f.startWrite(http2FrameGoAway, 0, 0)
	f.writeUint32(maxStreamID & (1<<31 - 1))
	f.writeUint32(uint32(code))
	f.writeBytes(debugData)
	return f.endWrite()
}

// An UnknownFrame is the frame type returned when the frame type is unknown
// or no specific frame type parser exists.
type http2UnknownFrame struct {
	http2FrameHeader
	p []byte
}

// Payload returns the frame's payload (after the header).  It is not
// valid to call this method after a subsequent call to
// Framer.ReadFrame, nor is it valid to retain the returned slice.
// The memory is owned by the Framer and is invalidated when the next
// frame is read.
func (f *http2UnknownFrame) Payload() []byte {
	f.checkValid()
	return f.p
}

func http2parseUnknownFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	return &http2UnknownFrame{fh, p}, nil
}

// A WindowUpdateFrame is used to implement flow control.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.9
type http2WindowUpdateFrame struct {
	http2FrameHeader
	Increment uint32 // never read with high bit set
}

func http2parseWindowUpdateFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_windowupdate_bad_len")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	inc := binary.BigEndian.Uint32(p[:4]) & 0x7fffffff // mask off high reserved bit
	if inc == 0 {
		// A receiver MUST treat the receipt of a
		// WINDOW_UPDATE frame with an flow control window
		// increment of 0 as a stream error (Section 5.4.2) of
		// type PROTOCOL_ERROR; errors on the connection flow
		// control window MUST be treated as a connection
		// error (Section 5.4.1).
		if fh.StreamID == 0 {
			countError("frame_windowupdate_zero_inc_conn")
			return nil, http2ConnectionError(http2ErrCodeProtocol)
		}
		countError("frame_windowupdate_zero_inc_stream")
		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}
	return &http2WindowUpdateFrame{
		http2FrameHeader: fh,
		Increment:        inc,
	}, nil
}

// WriteWindowUpdate writes a WINDOW_UPDATE frame.
// The increment value must be between 1 and 2,147,483,647, inclusive.
// If the Stream ID is zero, the window update applies to the
// connection as a whole.
func (f *http2Framer) WriteWindowUpdate(streamID, incr uint32) error {
	// "The legal range for the increment to the flow control window is 1 to 2^31-1 (2,147,483,647) octets."
	if (incr < 1 || incr > 2147483647) && !f.AllowIllegalWrites {
		return errors.New("illegal window increment value")
	}
	f.startWrite(http2FrameWindowUpdate, 0, streamID)
	f.writeUint32(incr)
	return f.endWrite()
}

// A HeadersFrame is used to open a stream and additionally carries a
// header block fragment.
type http2HeadersFrame struct {
	http2FrameHeader

	// Priority is set if FlagHeadersPriority is set in the FrameHeader.
	Priority http2PriorityParam

	headerFragBuf []byte // not owned
}

func (f *http2HeadersFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2HeadersFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndHeaders)
}

func (f *http2HeadersFrame) StreamEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersEndStream)
}

func (f *http2HeadersFrame) HasPriority() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagHeadersPriority)
}

func http2parseHeadersFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	hf := &http2HeadersFrame{
		http2FrameHeader: fh,
	}
	if fh.StreamID == 0 {
		// HEADERS frames MUST be associated with a stream. If a HEADERS frame
		// is received whose stream identifier field is 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR.
		countError("frame_headers_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "HEADERS frame with stream ID 0"}
	}
	var padLength uint8
	if fh.Flags.Has(http2FlagHeadersPadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_headers_pad_short")
			return
		}
	}
	if fh.Flags.Has(http2FlagHeadersPriority) {
		var v uint32
		p, v, err = http2readUint32(p)
		if err != nil {
			countError("frame_headers_prio_short")
			return nil, err
		}
		hf.Priority.StreamDep = v & 0x7fffffff
		hf.Priority.Exclusive = (v != hf.Priority.StreamDep) // high bit was set
		p, hf.Priority.Weight, err = http2readByte(p)
		if err != nil {
			countError("frame_headers_prio_weight_short")
			return nil, err
		}
	}
	if len(p)-int(padLength) < 0 {
		countError("frame_headers_pad_too_big")
		return nil, http2streamError(fh.StreamID, http2ErrCodeProtocol)
	}
	hf.headerFragBuf = p[:len(p)-int(padLength)]
	return hf, nil
}

// HeadersFrameParam are the parameters for writing a HEADERS frame.
type http2HeadersFrameParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32
	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndStream indicates that the header block is the last that
	// the endpoint will send for the identified stream. Setting
	// this flag causes the stream to enter one of "half closed"
	// states.
	EndStream bool

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8

	// Priority, if non-zero, includes stream priority information
	// in the HEADER frame.
	Priority http2PriorityParam
}

// WriteHeaders writes a single HEADERS frame.
//
// This is a low-level header writing method. Encoding headers and
// splitting them into any necessary CONTINUATION frames is handled
// elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteHeaders(p http2HeadersFrameParam) error {
	if !http2validStreamID(p.StreamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagHeadersPadded
	}
	if p.EndStream {
		flags |= http2FlagHeadersEndStream
	}
	if p.EndHeaders {
		flags |= http2FlagHeadersEndHeaders
	}
	if !p.Priority.IsZero() {
		flags |= http2FlagHeadersPriority
	}
	f.startWrite(http2FrameHeaders, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	if !p.Priority.IsZero() {
		v := p.Priority.StreamDep
		if !http2validStreamIDOrZero(v) && !f.AllowIllegalWrites {
			return http2errDepStreamID
		}
		if p.Priority.Exclusive {
			v |= 1 << 31
		}
		f.writeUint32(v)
		f.writeByte(p.Priority.Weight)
	}
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// A PriorityFrame specifies the sender-advised priority of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.3
type http2PriorityFrame struct {
	http2FrameHeader
	http2PriorityParam
}

// PriorityParam are the stream prioritzation parameters.
type http2PriorityParam struct {
	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

func (p http2PriorityParam) IsZero() bool {
	return p == http2PriorityParam{}
}

func http2parsePriorityFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), payload []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_priority_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "PRIORITY frame with stream ID 0"}
	}
	if len(payload) != 5 {
		countError("frame_priority_bad_length")
		return nil, http2connError{http2ErrCodeFrameSize, fmt.Sprintf("PRIORITY frame payload size was %d; want 5", len(payload))}
	}
	v := binary.BigEndian.Uint32(payload[:4])
	streamID := v & 0x7fffffff // mask off high bit
	return &http2PriorityFrame{
		http2FrameHeader: fh,
		http2PriorityParam: http2PriorityParam{
			Weight:    payload[4],
			StreamDep: streamID,
			Exclusive: streamID != v, // was high bit set?
		},
	}, nil
}

// WritePriority writes a PRIORITY frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePriority(streamID uint32, p http2PriorityParam) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	if !http2validStreamIDOrZero(p.StreamDep) {
		return http2errDepStreamID
	}
	f.startWrite(http2FramePriority, 0, streamID)
	v := p.StreamDep
	if p.Exclusive {
		v |= 1 << 31
	}
	f.writeUint32(v)
	f.writeByte(p.Weight)
	return f.endWrite()
}

// A RSTStreamFrame allows for abnormal termination of a stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.4
type http2RSTStreamFrame struct {
	http2FrameHeader
	ErrCode http2ErrCode
}

func http2parseRSTStreamFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if len(p) != 4 {
		countError("frame_rststream_bad_len")
		return nil, http2ConnectionError(http2ErrCodeFrameSize)
	}
	if fh.StreamID == 0 {
		countError("frame_rststream_zero_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	return &http2RSTStreamFrame{fh, http2ErrCode(binary.BigEndian.Uint32(p[:4]))}, nil
}

// WriteRSTStream writes a RST_STREAM frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteRSTStream(streamID uint32, code http2ErrCode) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	f.startWrite(http2FrameRSTStream, 0, streamID)
	f.writeUint32(uint32(code))
	return f.endWrite()
}

// A ContinuationFrame is used to continue a sequence of header block fragments.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.10
type http2ContinuationFrame struct {
	http2FrameHeader
	headerFragBuf []byte
}

func http2parseContinuationFrame(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (http2Frame, error) {
	if fh.StreamID == 0 {
		countError("frame_continuation_zero_stream")
		return nil, http2connError{http2ErrCodeProtocol, "CONTINUATION frame with stream ID 0"}
	}
	return &http2ContinuationFrame{fh, p}, nil
}

func (f *http2ContinuationFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2ContinuationFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagContinuationEndHeaders)
}

// WriteContinuation writes a CONTINUATION frame.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WriteContinuation(streamID uint32, endHeaders bool, headerBlockFragment []byte) error {
	if !http2validStreamID(streamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if endHeaders {
		flags |= http2FlagContinuationEndHeaders
	}
	f.startWrite(http2FrameContinuation, flags, streamID)
	f.wbuf = append(f.wbuf, headerBlockFragment...)
	return f.endWrite()
}

// A PushPromiseFrame is used to initiate a server stream.
// See https://httpwg.org/specs/rfc7540.html#rfc.section.6.6
type http2PushPromiseFrame struct {
	http2FrameHeader
	PromiseID     uint32
	headerFragBuf []byte // not owned
}

func (f *http2PushPromiseFrame) HeaderBlockFragment() []byte {
	f.checkValid()
	return f.headerFragBuf
}

func (f *http2PushPromiseFrame) HeadersEnded() bool {
	return f.http2FrameHeader.Flags.Has(http2FlagPushPromiseEndHeaders)
}

func http2parsePushPromise(_ *http2frameCache, fh http2FrameHeader, countError func(string), p []byte) (_ http2Frame, err error) {
	pp := &http2PushPromiseFrame{
		http2FrameHeader: fh,
	}
	if pp.StreamID == 0 {
		// PUSH_PROMISE frames MUST be associated with an existing,
		// peer-initiated stream. The stream identifier of a
		// PUSH_PROMISE frame indicates the stream it is associated
		// with. If the stream identifier field specifies the value
		// 0x0, a recipient MUST respond with a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		countError("frame_pushpromise_zero_stream")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	// The PUSH_PROMISE frame includes optional padding.
	// Padding fields and flags are identical to those defined for DATA frames
	var padLength uint8
	if fh.Flags.Has(http2FlagPushPromisePadded) {
		if p, padLength, err = http2readByte(p); err != nil {
			countError("frame_pushpromise_pad_short")
			return
		}
	}

	p, pp.PromiseID, err = http2readUint32(p)
	if err != nil {
		countError("frame_pushpromise_promiseid_short")
		return
	}
	pp.PromiseID = pp.PromiseID & (1<<31 - 1)

	if int(padLength) > len(p) {
		// like the DATA frame, error out if padding is longer than the body.
		countError("frame_pushpromise_pad_too_big")
		return nil, http2ConnectionError(http2ErrCodeProtocol)
	}
	pp.headerFragBuf = p[:len(p)-int(padLength)]
	return pp, nil
}

// PushPromiseParam are the parameters for writing a PUSH_PROMISE frame.
type http2PushPromiseParam struct {
	// StreamID is the required Stream ID to initiate.
	StreamID uint32

	// PromiseID is the required Stream ID which this
	// Push Promises
	PromiseID uint32

	// BlockFragment is part (or all) of a Header Block.
	BlockFragment []byte

	// EndHeaders indicates that this frame contains an entire
	// header block and is not followed by any
	// CONTINUATION frames.
	EndHeaders bool

	// PadLength is the optional number of bytes of zeros to add
	// to this frame.
	PadLength uint8
}

// WritePushPromise writes a single PushPromise Frame.
//
// As with Header Frames, This is the low level call for writing
// individual frames. Continuation frames are handled elsewhere.
//
// It will perform exactly one Write to the underlying Writer.
// It is the caller's responsibility to not call other Write methods concurrently.
func (f *http2Framer) WritePushPromise(p http2PushPromiseParam) error {
	if !http2validStreamID(p.StreamID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	var flags http2Flags
	if p.PadLength != 0 {
		flags |= http2FlagPushPromisePadded
	}
	if p.EndHeaders {
		flags |= http2FlagPushPromiseEndHeaders
	}
	f.startWrite(http2FramePushPromise, flags, p.StreamID)
	if p.PadLength != 0 {
		f.writeByte(p.PadLength)
	}
	if !http2validStreamID(p.PromiseID) && !f.AllowIllegalWrites {
		return http2errStreamID
	}
	f.writeUint32(p.PromiseID)
	f.wbuf = append(f.wbuf, p.BlockFragment...)
	f.wbuf = append(f.wbuf, http2padZeros[:p.PadLength]...)
	return f.endWrite()
}

// WriteRawFrame writes a raw frame. This can be used to write
// extension frames unknown to this package.
func (f *http2Framer) WriteRawFrame(t http2FrameType, flags http2Flags, streamID uint32, payload []byte) error {
	f.startWrite(t, flags, streamID)
	f.writeBytes(payload)
	return f.endWrite()
}

func http2readByte(p []byte) (remain []byte, b byte, err error) {
	if len(p) == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[1:], p[0], nil
}

func http2readUint32(p []byte) (remain []byte, v uint32, err error) {
	if len(p) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return p[4:], binary.BigEndian.Uint32(p[:4]), nil
}

type http2streamEnder interface {
	StreamEnded() bool
}

type http2headersEnder interface {
	HeadersEnded() bool
}

type http2headersOrContinuation interface {
	http2headersEnder
	HeaderBlockFragment() []byte
}

// A MetaHeadersFrame is the representation of one HEADERS frame and
// zero or more contiguous CONTINUATION frames and the decoding of
// their HPACK-encoded contents.
//
// This type of frame does not appear on the wire and is only returned
// by the Framer when Framer.ReadMetaHeaders is set.
type http2MetaHeadersFrame struct {
	*http2HeadersFrame

	// Fields are the fields contained in the HEADERS and
	// CONTINUATION frames. The underlying slice is owned by the
	// Framer and must not be retained after the next call to
	// ReadFrame.
	//
	// Fields are guaranteed to be in the correct http2 order and
	// not have unknown pseudo header fields or invalid header
	// field names or values. Required pseudo header fields may be
	// missing, however. Use the MetaHeadersFrame.Pseudo accessor
	// method access pseudo headers.
	Fields []hpack.HeaderField

	// Truncated is whether the max header list size limit was hit
	// and Fields is incomplete. The hpack decoder state is still
	// valid, however.
	Truncated bool
}

// PseudoValue returns the given pseudo header field's value.
// The provided pseudo field should not contain the leading colon.
func (mh *http2MetaHeadersFrame) PseudoValue(pseudo string) string {
	for _, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return ""
		}
		if hf.Name[1:] == pseudo {
			return hf.Value
		}
	}
	return ""
}

// RegularFields returns the regular (non-pseudo) header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) RegularFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[i:]
		}
	}
	return nil
}

// PseudoFields returns the pseudo header fields of mh.
// The caller does not own the returned slice.
func (mh *http2MetaHeadersFrame) PseudoFields() []hpack.HeaderField {
	for i, hf := range mh.Fields {
		if !hf.IsPseudo() {
			return mh.Fields[:i]
		}
	}
	return mh.Fields
}

func (mh *http2MetaHeadersFrame) checkPseudos() error {
	var isRequest, isResponse bool
	pf := mh.PseudoFields()
	for i, hf := range pf {
		switch hf.Name {
		case ":method", ":path", ":scheme", ":authority":
			isRequest = true
		case ":status":
			isResponse = true
		default:
			return http2pseudoHeaderError(hf.Name)
		}
		// Check for duplicates.
		// This would be a bad algorithm, but N is 4.
		// And this doesn't allocate.
		for _, hf2 := range pf[:i] {
			if hf.Name == hf2.Name {
				return http2duplicatePseudoHeaderError(hf.Name)
			}
		}
	}
	if isRequest && isResponse {
		return http2errMixPseudoHeaderTypes
	}
	return nil
}

func (fr *http2Framer) maxHeaderStringLen() int {
	v := fr.maxHeaderListSize()
	if uint32(int(v)) == v {
		return int(v)
	}
	// They had a crazy big number for MaxHeaderBytes anyway,
	// so give them unlimited header lengths:
	return 0
}

// readMetaFrame returns 0 or more CONTINUATION frames from fr and
// merge them into the provided hf and returns a MetaHeadersFrame
// with the decoded hpack values.
func (fr *http2Framer) readMetaFrame(hf *http2HeadersFrame) (*http2MetaHeadersFrame, error) {
	if fr.AllowIllegalReads {
		return nil, errors.New("illegal use of AllowIllegalReads with ReadMetaHeaders")
	}
	mh := &http2MetaHeadersFrame{
		http2HeadersFrame: hf,
	}
	var remainSize = fr.maxHeaderListSize()
	var sawRegular bool

	var invalid error // pseudo header field errors
	hdec := fr.ReadMetaHeaders
	hdec.SetEmitEnabled(true)
	hdec.SetMaxStringLength(fr.maxHeaderStringLen())
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		if http2VerboseLogs && fr.logReads {
			fr.debugReadLoggerf("http2: decoded hpack field %+v", hf)
		}
		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			// Don't include the value in the error, because it may be sensitive.
			invalid = http2headerFieldValueError(hf.Name)
		}
		isPseudo := strings.HasPrefix(hf.Name, ":")
		if isPseudo {
			if sawRegular {
				invalid = http2errPseudoAfterRegular
			}
		} else {
			sawRegular = true
			if !http2validWireHeaderFieldName(hf.Name) {
				invalid = http2headerFieldNameError(hf.Name)
			}
		}

		if invalid != nil {
			hdec.SetEmitEnabled(false)
			return
		}

		size := hf.Size()
		if size > remainSize {
			hdec.SetEmitEnabled(false)
			mh.Truncated = true
			remainSize = 0
			return
		}
		remainSize -= size

		mh.Fields = append(mh.Fields, hf)
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	var hc http2headersOrContinuation = hf
	for {
		frag := hc.HeaderBlockFragment()

		// Avoid parsing large amounts of headers that we will then discard.
		// If the sender exceeds the max header list size by too much,
		// skip parsing the fragment and close the connection.
		//
		// "Too much" is either any CONTINUATION frame after we've already
		// exceeded the max header list size (in which case remainSize is 0),
		// or a frame whose encoded size is more than twice the remaining
		// header list bytes we're willing to accept.
		if int64(len(frag)) > int64(2*remainSize) {
			if http2VerboseLogs {
				log.Printf("http2: header list too large")
			}
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the struture of the server's frame writer makes this difficult.
			return nil, http2ConnectionError(http2ErrCodeProtocol)
		}

		// Also close the connection after any CONTINUATION frame following an
		// invalid header, since we stop tracking the size of the headers after
		// an invalid one.
		if invalid != nil {
			if http2VerboseLogs {
				log.Printf("http2: invalid header: %v", invalid)
			}
			// It would be nice to send a RST_STREAM before sending the GOAWAY,
			// but the struture of the server's frame writer makes this difficult.
			return nil, http2ConnectionError(http2ErrCodeProtocol)
		}

		if _, err := hdec.Write(frag); err != nil {
			return nil, http2ConnectionError(http2ErrCodeCompression)
		}

		if hc.HeadersEnded() {
			break
		}
		if f, err := fr.ReadFrame(); err != nil {
			return nil, err
		} else {
			hc = f.(*http2ContinuationFrame) // guaranteed by checkFrameOrder
		}
	}

	mh.http2HeadersFrame.headerFragBuf = nil
	mh.http2HeadersFrame.invalidate()

	if err := hdec.Close(); err != nil {
		return nil, http2ConnectionError(http2ErrCodeCompression)
	}
	if invalid != nil {
		fr.errDetail = invalid
		if http2VerboseLogs {
			log.Printf("http2: invalid header: %v", invalid)
		}
		return nil, http2StreamError{mh.StreamID, http2ErrCodeProtocol, invalid}
	}
	if err := mh.checkPseudos(); err != nil {
		fr.errDetail = err
		if http2VerboseLogs {
			log.Printf("http2: invalid pseudo headers: %v", err)
		}
		return nil, http2StreamError{mh.StreamID, http2ErrCodeProtocol, err}
	}
	return mh, nil
}

func http2summarizeFrame(f http2Frame) string {
	var buf bytes.Buffer
	f.Header().writeDebug(&buf)
	switch f := f.(type) {
	case *http2SettingsFrame:
		n := 0
		f.ForeachSetting(func(s http2Setting) error {
			n++
			if n == 1 {
				buf.WriteString(", settings:")
			}
			fmt.Fprintf(&buf, " %v=%v,", s.ID, s.Val)
			return nil
		})
		if n > 0 {
			buf.Truncate(buf.Len() - 1) // remove trailing comma
		}
	case *http2DataFrame:
		data := f.Data()
		const max = 256
		if len(data) > max {
			data = data[:max]
		}
		fmt.Fprintf(&buf, " data=%q", data)
		if len(f.Data()) > max {
			fmt.Fprintf(&buf, " (%d bytes omitted)", len(f.Data())-max)
		}
	case *http2WindowUpdateFrame:
		if f.StreamID == 0 {
			buf.WriteString(" (conn)")
		}
		fmt.Fprintf(&buf, " incr=%v", f.Increment)
	case *http2PingFrame:
		fmt.Fprintf(&buf, " ping=%q", f.Data[:])
	case *http2GoAwayFrame:
		fmt.Fprintf(&buf, " LastStreamID=%v ErrCode=%v Debug=%q",
			f.LastStreamID, f.ErrCode, f.debugData)
	case *http2RSTStreamFrame:
		fmt.Fprintf(&buf, " ErrCode=%v", f.ErrCode)
	}
	return buf.String()
}

func http2traceHasWroteHeaderField(trace *httptrace.ClientTrace) bool {
	return trace != nil && trace.WroteHeaderField != nil
}

func http2traceWroteHeaderField(trace *httptrace.ClientTrace, k, v string) {
	if trace != nil && trace.WroteHeaderField != nil {
		trace.WroteHeaderField(k, []string{v})
	}
}

func http2traceGot1xxResponseFunc(trace *httptrace.ClientTrace) func(int, textproto.MIMEHeader) error {
	if trace != nil {
		return trace.Got1xxResponse
	}
	return nil
}

// dialTLSWithContext uses tls.Dialer, added in Go 1.15, to open a TLS
// connection.
func (t *http2Transport) dialTLSWithContext(ctx context.Context, network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		Config: cfg,
	}
	cn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsCn := cn.(*tls.Conn) // DialContext comment promises this will always succeed
	return tlsCn, nil
}

func http2tlsUnderlyingConn(tc *tls.Conn) net.Conn {
	return tc.NetConn()
}

var http2DebugGoroutines = os.Getenv("DEBUG_HTTP2_GOROUTINES") == "1"

type http2goroutineLock uint64

func http2newGoroutineLock() http2goroutineLock {
	if !http2DebugGoroutines {
		return 0
	}
	return http2goroutineLock(http2curGoroutineID())
}

func (g http2goroutineLock) check() {
	if !http2DebugGoroutines {
		return
	}
	if http2curGoroutineID() != uint64(g) {
		panic("running on the wrong goroutine")
	}
}

func (g http2goroutineLock) checkNotOn() {
	if !http2DebugGoroutines {
		return
	}
	if http2curGoroutineID() == uint64(g) {
		panic("running on the wrong goroutine")
	}
}

var http2goroutineSpace = []byte("goroutine ")

func http2curGoroutineID() uint64 {
	bp := http2littleBuf.Get().(*[]byte)
	defer http2littleBuf.Put(bp)
	b := *bp
	b = b[:runtime.Stack(b, false)]
	// Parse the 4707 out of "goroutine 4707 ["
	b = bytes.TrimPrefix(b, http2goroutineSpace)
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		panic(fmt.Sprintf("No space found in %q", b))
	}
	b = b[:i]
	n, err := http2parseUintBytes(b, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse goroutine ID out of %q: %v", b, err))
	}
	return n
}

var http2littleBuf = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64)
		return &buf
	},
}

// parseUintBytes is like strconv.ParseUint, but using a []byte.
func http2parseUintBytes(s []byte, base int, bitSize int) (n uint64, err error) {
	var cutoff, maxVal uint64

	if bitSize == 0 {
		bitSize = int(strconv.IntSize)
	}

	s0 := s
	switch {
	case len(s) < 1:
		err = strconv.ErrSyntax
		goto Error

	case 2 <= base && base <= 36:
		// valid base; nothing to do

	case base == 0:
		// Look for octal, hex prefix.
		switch {
		case s[0] == '0' && len(s) > 1 && (s[1] == 'x' || s[1] == 'X'):
			base = 16
			s = s[2:]
			if len(s) < 1 {
				err = strconv.ErrSyntax
				goto Error
			}
		case s[0] == '0':
			base = 8
		default:
			base = 10
		}

	default:
		err = errors.New("invalid base " + strconv.Itoa(base))
		goto Error
	}

	n = 0
	cutoff = http2cutoff64(base)
	maxVal = 1<<uint(bitSize) - 1

	for i := 0; i < len(s); i++ {
		var v byte
		d := s[i]
		switch {
		case '0' <= d && d <= '9':
			v = d - '0'
		case 'a' <= d && d <= 'z':
			v = d - 'a' + 10
		case 'A' <= d && d <= 'Z':
			v = d - 'A' + 10
		default:
			n = 0
			err = strconv.ErrSyntax
			goto Error
		}
		if int(v) >= base {
			n = 0
			err = strconv.ErrSyntax
			goto Error
		}

		if n >= cutoff {
			// n*base overflows
			n = 1<<64 - 1
			err = strconv.ErrRange
			goto Error
		}
		n *= uint64(base)

		n1 := n + uint64(v)
		if n1 < n || n1 > maxVal {
			// n+v overflows
			n = 1<<64 - 1
			err = strconv.ErrRange
			goto Error
		}
		n = n1
	}

	return n, nil

Error:
	return n, &strconv.NumError{Func: "ParseUint", Num: string(s0), Err: err}
}

// Return the first number n such that n*base >= 1<<64.
func http2cutoff64(base int) uint64 {
	if base < 2 {
		return 0
	}
	return (1<<64-1)/uint64(base) + 1
}

var (
	http2commonBuildOnce   sync.Once
	http2commonLowerHeader map[string]string // Go-Canonical-Case -> lower-case
	http2commonCanonHeader map[string]string // lower-case -> Go-Canonical-Case
)

func http2buildCommonHeaderMapsOnce() {
	http2commonBuildOnce.Do(http2buildCommonHeaderMaps)
}

func http2buildCommonHeaderMaps() {
	common := []string{
		"accept",
		"accept-charset",
		"accept-encoding",
		"accept-language",
		"accept-ranges",
		"age",
		"access-control-allow-credentials",
		"access-control-allow-headers",
		"access-control-allow-methods",
		"access-control-allow-origin",
		"access-control-expose-headers",
		"access-control-max-age",
		"access-control-request-headers",
		"access-control-request-method",
		"allow",
		"authorization",
		"cache-control",
		"content-disposition",
		"content-encoding",
		"content-language",
		"content-length",
		"content-location",
		"content-range",
		"content-type",
		"cookie",
		"date",
		"etag",
		"expect",
		"expires",
		"from",
		"host",
		"if-match",
		"if-modified-since",
		"if-none-match",
		"if-unmodified-since",
		"last-modified",
		"link",
		"location",
		"max-forwards",
		"origin",
		"proxy-authenticate",
		"proxy-authorization",
		"range",
		"referer",
		"refresh",
		"retry-after",
		"server",
		"set-cookie",
		"strict-transport-security",
		"trailer",
		"transfer-encoding",
		"user-agent",
		"vary",
		"via",
		"www-authenticate",
		"x-forwarded-for",
		"x-forwarded-proto",
	}
	http2commonLowerHeader = make(map[string]string, len(common))
	http2commonCanonHeader = make(map[string]string, len(common))
	for _, v := range common {
		chk := http.CanonicalHeaderKey(v)
		http2commonLowerHeader[chk] = v
		http2commonCanonHeader[v] = chk
	}
}

func http2lowerHeader(v string) (lower string, ascii bool) {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonLowerHeader[v]; ok {
		return s, true
	}
	return http2asciiToLower(v)
}

func http2canonicalHeader(v string) string {
	http2buildCommonHeaderMapsOnce()
	if s, ok := http2commonCanonHeader[v]; ok {
		return s
	}
	return http.CanonicalHeaderKey(v)
}

var (
	http2VerboseLogs    bool
	http2logFrameWrites bool
	http2logFrameReads  bool
	http2inTests        bool
)

func init() {
	e := os.Getenv("GODEBUG")
	if strings.Contains(e, "http2debug=1") {
		http2VerboseLogs = true
	}
	if strings.Contains(e, "http2debug=2") {
		http2VerboseLogs = true
		http2logFrameWrites = true
		http2logFrameReads = true
	}
}

const (
	// ClientPreface is the string that must be sent by new
	// connections from clients.
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// SETTINGS_MAX_FRAME_SIZE default
	// https://httpwg.org/specs/rfc7540.html#rfc.section.6.5.2
	http2initialMaxFrameSize = 16384

	// NextProtoTLS is the NPN/ALPN protocol negotiated during
	// HTTP/2's TLS setup.
	http2NextProtoTLS = "h2"

	// https://httpwg.org/specs/rfc7540.html#SettingValues
	http2initialHeaderTableSize = 4096

	http2initialWindowSize = 65535 // 6.9.2 Initial Flow Control Window Size

	http2defaultMaxReadFrameSize = 1 << 20
)

var (
	http2clientPreface = []byte(http2ClientPreface)
)

type http2streamState int

// HTTP/2 stream states.
//
// See http://tools.ietf.org/html/rfc7540#section-5.1.
//
// For simplicity, the server code merges "reserved (local)" into
// "half-closed (remote)". This is one less state transition to track.
// The only downside is that we send PUSH_PROMISEs slightly less
// liberally than allowable. More discussion here:
// https://lists.w3.org/Archives/Public/ietf-http-wg/2016JulSep/0599.html
//
// "reserved (remote)" is omitted since the client code does not
// support server push.
const (
	http2stateIdle http2streamState = iota
	http2stateOpen
	http2stateHalfClosedLocal
	http2stateHalfClosedRemote
	http2stateClosed
)

var http2stateName = [...]string{
	http2stateIdle:             "Idle",
	http2stateOpen:             "Open",
	http2stateHalfClosedLocal:  "HalfClosedLocal",
	http2stateHalfClosedRemote: "HalfClosedRemote",
	http2stateClosed:           "Closed",
}

func (st http2streamState) String() string {
	return http2stateName[st]
}

// Setting is a setting parameter: which setting it is, and its value.
type http2Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	ID http2SettingID

	// Val is the value.
	Val uint32
}

func (s http2Setting) String() string {
	return fmt.Sprintf("[%v = %d]", s.ID, s.Val)
}

// Valid reports whether the setting is valid.
func (s http2Setting) Valid() error {
	// Limits and error codes from 6.5.2 Defined SETTINGS Parameters
	switch s.ID {
	case http2SettingEnablePush:
		if s.Val != 1 && s.Val != 0 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	case http2SettingInitialWindowSize:
		if s.Val > 1<<31-1 {
			return http2ConnectionError(http2ErrCodeFlowControl)
		}
	case http2SettingMaxFrameSize:
		if s.Val < 16384 || s.Val > 1<<24-1 {
			return http2ConnectionError(http2ErrCodeProtocol)
		}
	}
	return nil
}

// A SettingID is an HTTP/2 setting as defined in
// https://httpwg.org/specs/rfc7540.html#iana-settings
type http2SettingID uint16

const (
	http2SettingHeaderTableSize      http2SettingID = 0x1
	http2SettingEnablePush           http2SettingID = 0x2
	http2SettingMaxConcurrentStreams http2SettingID = 0x3
	http2SettingInitialWindowSize    http2SettingID = 0x4
	http2SettingMaxFrameSize         http2SettingID = 0x5
	http2SettingMaxHeaderListSize    http2SettingID = 0x6
)

var http2settingName = map[http2SettingID]string{
	http2SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	http2SettingEnablePush:           "ENABLE_PUSH",
	http2SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	http2SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	http2SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	http2SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

func (s http2SettingID) String() string {
	if v, ok := http2settingName[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN_SETTING_%d", uint16(s))
}

// validWireHeaderFieldName reports whether v is a valid header field
// name (key). See httpguts.ValidHeaderName for the base rules.
//
// Further, http2 says:
//
//	"Just as in HTTP/1.x, header field names are strings of ASCII
//	characters that are compared in a case-insensitive
//	fashion. However, header field names MUST be converted to
//	lowercase prior to their encoding in HTTP/2. "
func http2validWireHeaderFieldName(v string) bool {
	if len(v) == 0 {
		return false
	}
	for _, r := range v {
		if !httpguts.IsTokenRune(r) {
			return false
		}
		if 'A' <= r && r <= 'Z' {
			return false
		}
	}
	return true
}

func http2httpCodeString(code int) string {
	switch code {
	case 200:
		return "200"
	case 404:
		return "404"
	}
	return strconv.Itoa(code)
}

// from pkg io
type http2stringWriter interface {
	WriteString(s string) (n int, err error)
}

// A gate lets two goroutines coordinate their activities.
type http2gate chan struct{}

func (g http2gate) Done() { g <- struct{}{} }

func (g http2gate) Wait() { <-g }

// A closeWaiter is like a sync.WaitGroup but only goes 1 to 0 (open to closed).
type http2closeWaiter chan struct{}

// Init makes a closeWaiter usable.
// It exists because so a closeWaiter value can be placed inside a
// larger struct and have the Mutex and Cond's memory in the same
// allocation.
func (cw *http2closeWaiter) Init() {
	*cw = make(chan struct{})
}

// Close marks the closeWaiter as closed and unblocks any waiters.
func (cw http2closeWaiter) Close() {
	close(cw)
}

// Wait waits for the closeWaiter to become closed.
func (cw http2closeWaiter) Wait() {
	<-cw
}

// bufferedWriter is a buffered writer that writes to w.
// Its buffered writer is lazily allocated as needed, to minimize
// idle memory usage with many connections.
type http2bufferedWriter struct {
	_  http2incomparable
	w  io.Writer     // immutable
	bw *bufio.Writer // non-nil when data is buffered
}

func http2newBufferedWriter(w io.Writer) *http2bufferedWriter {
	return &http2bufferedWriter{w: w}
}

// bufWriterPoolBufferSize is the size of bufio.Writer's
// buffers created using bufWriterPool.
//
// TODO: pick a less arbitrary value? this is a bit under
// (3 x typical 1500 byte MTU) at least. Other than that,
// not much thought went into it.
const http2bufWriterPoolBufferSize = 4 << 10

var http2bufWriterPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, http2bufWriterPoolBufferSize)
	},
}

func (w *http2bufferedWriter) Available() int {
	if w.bw == nil {
		return http2bufWriterPoolBufferSize
	}
	return w.bw.Available()
}

func (w *http2bufferedWriter) Write(p []byte) (n int, err error) {
	if w.bw == nil {
		bw := http2bufWriterPool.Get().(*bufio.Writer)
		bw.Reset(w.w)
		w.bw = bw
	}
	return w.bw.Write(p)
}

func (w *http2bufferedWriter) Flush() error {
	bw := w.bw
	if bw == nil {
		return nil
	}
	err := bw.Flush()
	bw.Reset(nil)
	http2bufWriterPool.Put(bw)
	w.bw = nil
	return err
}

func http2mustUint31(v int32) uint32 {
	if v < 0 || v > 2147483647 {
		panic("out of range")
	}
	return uint32(v)
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 7230, section 3.3.
func http2bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

type http2httpError struct {
	_       http2incomparable
	msg     string
	timeout bool
}

func (e *http2httpError) Error() string { return e.msg }

func (e *http2httpError) Timeout() bool { return e.timeout }

func (e *http2httpError) Temporary() bool { return true }

var http2errTimeout error = &http2httpError{msg: "http2: timeout awaiting response headers", timeout: true}

type http2connectionStater interface {
	ConnectionState() tls.ConnectionState
}

var http2sorterPool = sync.Pool{New: func() interface{} { return new(http2sorter) }}

type http2sorter struct {
	v []string // owned by sorter
}

func (s *http2sorter) Len() int { return len(s.v) }

func (s *http2sorter) Swap(i, j int) { s.v[i], s.v[j] = s.v[j], s.v[i] }

func (s *http2sorter) Less(i, j int) bool { return s.v[i] < s.v[j] }

// Keys returns the sorted keys of h.
//
// The returned slice is only valid until s used again or returned to
// its pool.
func (s *http2sorter) Keys(h http.Header) []string {
	keys := s.v[:0]
	for k := range h {
		keys = append(keys, k)
	}
	s.v = keys
	sort.Sort(s)
	return keys
}

func (s *http2sorter) SortStrings(ss []string) {
	// Our sorter works on s.v, which sorter owns, so
	// stash it away while we sort the user's buffer.
	save := s.v
	s.v = ss
	sort.Sort(s)
	s.v = save
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//   - a non-empty string starting with '/'
//   - the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func http2validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type http2incomparable [0]func()

// pipe is a goroutine-safe io.Reader/io.Writer pair. It's like
// io.Pipe except there are no PipeReader/PipeWriter halves, and the
// underlying buffer is an interface. (io.Pipe is always unbuffered)
type http2pipe struct {
	mu       sync.Mutex
	c        sync.Cond       // c.L lazily initialized to &p.mu
	b        http2pipeBuffer // nil when done reading
	unread   int             // bytes unread when done
	err      error           // read error once empty. non-nil means closed.
	breakErr error           // immediate read error (caller doesn't see rest of b)
	donec    chan struct{}   // closed on error
	readFn   func()          // optional code to run in Read before error
}

type http2pipeBuffer interface {
	Len() int
	io.Writer
	io.Reader
}

// setBuffer initializes the pipe buffer.
// It has no effect if the pipe is already closed.
func (p *http2pipe) setBuffer(b http2pipeBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.breakErr != nil {
		return
	}
	p.b = b
}

func (p *http2pipe) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.b == nil {
		return p.unread
	}
	return p.b.Len()
}

// Read waits until data is available and copies bytes
// from the buffer into p.
func (p *http2pipe) Read(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	for {
		if p.breakErr != nil {
			return 0, p.breakErr
		}
		if p.b != nil && p.b.Len() > 0 {
			return p.b.Read(d)
		}
		if p.err != nil {
			if p.readFn != nil {
				p.readFn()     // e.g. copy trailers
				p.readFn = nil // not sticky like p.err
			}
			p.b = nil
			return 0, p.err
		}
		p.c.Wait()
	}
}

var http2errClosedPipeWrite = errors.New("write on closed buffer")

// Write copies bytes from p into the buffer and wakes a reader.
// It is an error to write more data than the buffer can hold.
func (p *http2pipe) Write(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if p.err != nil || p.breakErr != nil {
		return 0, http2errClosedPipeWrite
	}
	return p.b.Write(d)
}

// CloseWithError causes the next Read (waking up a current blocked
// Read if needed) to return the provided err after all data has been
// read.
//
// The error must be non-nil.
func (p *http2pipe) CloseWithError(err error) { p.closeWithError(&p.err, err, nil) }

// BreakWithError causes the next Read (waking up a current blocked
// Read if needed) to return the provided err immediately, without
// waiting for unread data.
func (p *http2pipe) BreakWithError(err error) { p.closeWithError(&p.breakErr, err, nil) }

// closeWithErrorAndCode is like CloseWithError but also sets some code to run
// in the caller's goroutine before returning the error.
func (p *http2pipe) closeWithErrorAndCode(err error, fn func()) { p.closeWithError(&p.err, err, fn) }

func (p *http2pipe) closeWithError(dst *error, err error, fn func()) {
	if err == nil {
		panic("err must be non-nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if *dst != nil {
		// Already been done.
		return
	}
	p.readFn = fn
	if dst == &p.breakErr {
		if p.b != nil {
			p.unread += p.b.Len()
		}
		p.b = nil
	}
	*dst = err
	p.closeDoneLocked()
}

// requires p.mu be held.
func (p *http2pipe) closeDoneLocked() {
	if p.donec == nil {
		return
	}
	// Close if unclosed. This isn't racy since we always
	// hold p.mu while closing.
	select {
	case <-p.donec:
	default:
		close(p.donec)
	}
}

// Err returns the error (if any) first set by BreakWithError or CloseWithError.
func (p *http2pipe) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.breakErr != nil {
		return p.breakErr
	}
	return p.err
}

// Done returns a channel which is closed if and when this pipe is closed
// with CloseWithError.
func (p *http2pipe) Done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.donec == nil {
		p.donec = make(chan struct{})
		if p.err != nil || p.breakErr != nil {
			// Already hit an error.
			p.closeDoneLocked()
		}
	}
	return p.donec
}

const (
	http2prefaceTimeout         = 10 * time.Second
	http2firstSettingsTimeout   = 2 * time.Second // should be in-flight with preface anyway
	http2handlerChunkWriteSize  = 4 << 10
	http2defaultMaxStreams      = 250 // TODO: make this 100 as the GFE seems to?
	http2maxQueuedControlFrames = 10000
)

var (
	http2errClientDisconnected = errors.New("client disconnected")
	http2errClosedBody         = errors.New("body closed by handler")
	http2errHandlerComplete    = errors.New("http2: request body closed due to handler exiting")
	http2errStreamClosed       = errors.New("http2: stream closed")
)

var http2responseWriterStatePool = sync.Pool{
	New: func() interface{} {
		rws := &http2responseWriterState{}
		rws.bw = bufio.NewWriterSize(http2chunkWriter{rws}, http2handlerChunkWriteSize)
		return rws
	},
}

// Test hooks.
var (
	http2testHookOnConn        func()
	http2testHookGetServerConn func(*http2serverConn)
	http2testHookOnPanicMu     *sync.Mutex // nil except in tests
	http2testHookOnPanic       func(sc *http2serverConn, panicVal interface{}) (rePanic bool)
)

// Server is an HTTP/2 server.
type http2Server struct {
	// MaxHandlers limits the number of http.Handler ServeHTTP goroutines
	// which may run at a time over all connections.
	// Negative or zero no limit.
	// TODO: implement
	MaxHandlers int

	// MaxConcurrentStreams optionally specifies the number of
	// concurrent streams that each client may have open at a
	// time. This is unrelated to the number of http.Handler goroutines
	// which may be active globally, which is MaxHandlers.
	// If zero, MaxConcurrentStreams defaults to at least 100, per
	// the HTTP/2 spec's recommendations.
	MaxConcurrentStreams uint32

	// MaxDecoderHeaderTableSize optionally specifies the http2
	// SETTINGS_HEADER_TABLE_SIZE to send in the initial settings frame. It
	// informs the remote endpoint of the maximum size of the header compression
	// table used to decode header blocks, in octets. If zero, the default value
	// of 4096 is used.
	MaxDecoderHeaderTableSize uint32

	// MaxEncoderHeaderTableSize optionally specifies an upper limit for the
	// header compression table used for encoding request headers. Received
	// SETTINGS_HEADER_TABLE_SIZE settings are capped at this limit. If zero,
	// the default value of 4096 is used.
	MaxEncoderHeaderTableSize uint32

	// MaxReadFrameSize optionally specifies the largest frame
	// this server is willing to read. A valid value is between
	// 16k and 16M, inclusive. If zero or otherwise invalid, a
	// default value is used.
	MaxReadFrameSize uint32

	// PermitProhibitedCipherSuites, if true, permits the use of
	// cipher suites prohibited by the HTTP/2 spec.
	PermitProhibitedCipherSuites bool

	// IdleTimeout specifies how long until idle clients should be
	// closed with a GOAWAY frame. PING frames are not considered
	// activity for the purposes of IdleTimeout.
	IdleTimeout time.Duration

	// MaxUploadBufferPerConnection is the size of the initial flow
	// control window for each connections. The HTTP/2 spec does not
	// allow this to be smaller than 65535 or larger than 2^32-1.
	// If the value is outside this range, a default value will be
	// used instead.
	MaxUploadBufferPerConnection int32

	// MaxUploadBufferPerStream is the size of the initial flow control
	// window for each stream. The HTTP/2 spec does not allow this to
	// be larger than 2^32-1. If the value is zero or larger than the
	// maximum, a default value will be used instead.
	MaxUploadBufferPerStream int32

	// NewWriteScheduler constructs a write scheduler for a connection.
	// If nil, a default scheduler is chosen.
	NewWriteScheduler func() http2WriteScheduler

	// CountError, if non-nil, is called on HTTP/2 server errors.
	// It's intended to increment a metric for monitoring, such
	// as an expvar or Prometheus metric.
	// The errType consists of only ASCII word characters.
	CountError func(errType string)

	// Internal state. This is a pointer (rather than embedded directly)
	// so that we don't embed a Mutex in this struct, which will make the
	// struct non-copyable, which might break some callers.
	state *http2serverInternalState
}

func (s *http2Server) initialConnRecvWindowSize() int32 {
	if s.MaxUploadBufferPerConnection >= http2initialWindowSize {
		return s.MaxUploadBufferPerConnection
	}
	return 1 << 20
}

func (s *http2Server) initialStreamRecvWindowSize() int32 {
	if s.MaxUploadBufferPerStream > 0 {
		return s.MaxUploadBufferPerStream
	}
	return 1 << 20
}

func (s *http2Server) maxReadFrameSize() uint32 {
	if v := s.MaxReadFrameSize; v >= http2minMaxFrameSize && v <= http2maxFrameSize {
		return v
	}
	return http2defaultMaxReadFrameSize
}

func (s *http2Server) maxConcurrentStreams() uint32 {
	if v := s.MaxConcurrentStreams; v > 0 {
		return v
	}
	return http2defaultMaxStreams
}

func (s *http2Server) maxDecoderHeaderTableSize() uint32 {
	if v := s.MaxDecoderHeaderTableSize; v > 0 {
		return v
	}
	return http2initialHeaderTableSize
}

func (s *http2Server) maxEncoderHeaderTableSize() uint32 {
	if v := s.MaxEncoderHeaderTableSize; v > 0 {
		return v
	}
	return http2initialHeaderTableSize
}

// maxQueuedControlFrames is the maximum number of control frames like
// SETTINGS, PING and RST_STREAM that will be queued for writing before
// the connection is closed to prevent memory exhaustion attacks.
func (s *http2Server) maxQueuedControlFrames() int {
	// TODO: if anybody asks, add a Server field, and remember to define the
	// behavior of negative values.
	return http2maxQueuedControlFrames
}

type http2serverInternalState struct {
	mu          sync.Mutex
	activeConns map[*http2serverConn]struct{}
}

func (s *http2serverInternalState) registerConn(sc *http2serverConn) {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	s.activeConns[sc] = struct{}{}
	s.mu.Unlock()
}

func (s *http2serverInternalState) unregisterConn(sc *http2serverConn) {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	delete(s.activeConns, sc)
	s.mu.Unlock()
}

func (s *http2serverInternalState) startGracefulShutdown() {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	for sc := range s.activeConns {
		sc.startGracefulShutdown()
	}
	s.mu.Unlock()
}

// ConfigureServer adds HTTP/2 support to a net/http Server.
//
// The configuration conf may be nil.
//
// ConfigureServer must be called before s begins serving.
func http2ConfigureServer(s *Server, conf *http2Server) error {
	if s == nil {
		panic("nil *http.Server")
	}
	if conf == nil {
		conf = new(http2Server)
	}
	conf.state = &http2serverInternalState{activeConns: make(map[*http2serverConn]struct{})}
	if h1, h2 := s, conf; h2.IdleTimeout == 0 {
		if h1.IdleTimeout != 0 {
			h2.IdleTimeout = h1.IdleTimeout
		} else {
			h2.IdleTimeout = h1.ReadTimeout
		}
	}
	s.RegisterOnShutdown(conf.state.startGracefulShutdown)

	if s.TLSConfig == nil {
		s.TLSConfig = new(tls.Config)
	} else if s.TLSConfig.CipherSuites != nil && s.TLSConfig.MinVersion < tls.VersionTLS13 {
		// If they already provided a TLS 1.0–1.2 CipherSuite list, return an
		// error if it is missing ECDHE_RSA_WITH_AES_128_GCM_SHA256 or
		// ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
		haveRequired := false
		for _, cs := range s.TLSConfig.CipherSuites {
			switch cs {
			case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// Alternative MTI cipher to not discourage ECDSA-only servers.
				// See http://golang.org/cl/30721 for further information.
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
				haveRequired = true
			}
		}
		if !haveRequired {
			return fmt.Errorf("http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)")
		}
	}

	// Note: not setting MinVersion to tls.VersionTLS12,
	// as we don't want to interfere with HTTP/1.1 traffic
	// on the user's server. We enforce TLS 1.2 later once
	// we accept a connection. Ideally this should be done
	// during next-proto selection, but using TLS <1.2 with
	// HTTP/2 is still the client's bug.

	s.TLSConfig.PreferServerCipherSuites = true

	if !http2strSliceContains(s.TLSConfig.NextProtos, http2NextProtoTLS) {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, http2NextProtoTLS)
	}
	if !http2strSliceContains(s.TLSConfig.NextProtos, "http/1.1") {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "http/1.1")
	}

	if s.TLSNextProto == nil {
		s.TLSNextProto = map[string]func(*Server, HttpsConn, http.Handler){}
	}
	protoHandler := func(hs *Server, c HttpsConn, h http.Handler) {
		if http2testHookOnConn != nil {
			http2testHookOnConn()
		}
		// The TLSNextProto interface predates contexts, so
		// the net/http package passes down its per-connection
		// base context via an exported but unadvertised
		// method on the Handler. This is for internal
		// net/http<=>http2 use only.
		var ctx context.Context
		type baseContexter interface {
			BaseContext() context.Context
		}
		if bc, ok := h.(baseContexter); ok {
			ctx = bc.BaseContext()
		}
		conf.ServeConn(c, &http2ServeConnOpts{
			Context:    ctx,
			Handler:    h,
			BaseConfig: hs,
		})
	}
	s.TLSNextProto[http2NextProtoTLS] = protoHandler
	return nil
}

// ServeConnOpts are options for the Server.ServeConn method.
type http2ServeConnOpts struct {
	// Context is the base context to use.
	// If nil, context.Background is used.
	Context context.Context

	// BaseConfig optionally sets the base configuration
	// for values. If nil, defaults are used.
	BaseConfig *Server

	// Handler specifies which handler to use for processing
	// requests. If nil, BaseConfig.Handler is used. If BaseConfig
	// or BaseConfig.Handler is nil, http.DefaultServeMux is used.
	Handler http.Handler

	// UpgradeRequest is an initial request received on a connection
	// undergoing an h2c upgrade. The request body must have been
	// completely read from the connection before calling ServeConn,
	// and the 101 Switching Protocols response written.
	UpgradeRequest *http.Request

	// Settings is the decoded contents of the HTTP2-Settings header
	// in an h2c upgrade request.
	Settings []byte

	// SawClientPreface is set if the HTTP/2 connection preface
	// has already been read from the connection.
	SawClientPreface bool
}

func (o *http2ServeConnOpts) context() context.Context {
	if o != nil && o.Context != nil {
		return o.Context
	}
	return context.Background()
}

func (o *http2ServeConnOpts) baseConfig() *Server {
	if o != nil && o.BaseConfig != nil {
		return o.BaseConfig
	}
	return new(Server)
}

func (o *http2ServeConnOpts) handler() http.Handler {
	if o != nil {
		if o.Handler != nil {
			return o.Handler
		}
		if o.BaseConfig != nil && o.BaseConfig.Handler != nil {
			return o.BaseConfig.Handler
		}
	}
	return http.DefaultServeMux
}

// ServeConn serves HTTP/2 requests on the provided connection and
// blocks until the connection is no longer readable.
//
// ServeConn starts speaking HTTP/2 assuming that c has not had any
// reads or writes. It writes its initial settings frame and expects
// to be able to read the preface and settings frame from the
// client. If c has a ConnectionState method like a *tls.Conn, the
// ConnectionState is used to verify the TLS ciphersuite and to set
// the Request.TLS field in Handlers.
//
// ServeConn does not support h2c by itself. Any h2c support must be
// implemented in terms of providing a suitably-behaving net.Conn.
//
// The opts parameter is optional. If nil, default values are used.
func (s *http2Server) ServeConn(c net.Conn, opts *http2ServeConnOpts) {
	baseCtx, cancel := http2serverConnBaseContext(c, opts)
	defer cancel()

	sc := &http2serverConn{
		srv:                         s,
		hs:                          opts.baseConfig(),
		conn:                        c,
		baseCtx:                     baseCtx,
		remoteAddrStr:               c.RemoteAddr().String(),
		bw:                          http2newBufferedWriter(c),
		handler:                     opts.handler(),
		streams:                     make(map[uint32]*http2stream),
		readFrameCh:                 make(chan http2readFrameResult),
		wantWriteFrameCh:            make(chan http2FrameWriteRequest, 8),
		serveMsgCh:                  make(chan interface{}, 8),
		wroteFrameCh:                make(chan http2frameWriteResult, 1), // buffered; one send in writeFrameAsync
		bodyReadCh:                  make(chan http2bodyReadMsg),         // buffering doesn't matter either way
		doneServing:                 make(chan struct{}),
		clientMaxStreams:            math.MaxUint32, // Section 6.5.2: "Initially, there is no limit to this value"
		advMaxStreams:               s.maxConcurrentStreams(),
		initialStreamSendWindowSize: http2initialWindowSize,
		maxFrameSize:                http2initialMaxFrameSize,
		serveG:                      http2newGoroutineLock(),
		pushEnabled:                 true,
		sawClientPreface:            opts.SawClientPreface,
	}

	s.state.registerConn(sc)
	defer s.state.unregisterConn(sc)

	// The net/http package sets the write deadline from the
	// http.Server.WriteTimeout during the TLS handshake, but then
	// passes the connection off to us with the deadline already set.
	// Write deadlines are set per stream in serverConn.newStream.
	// Disarm the net.Conn write deadline here.
	if sc.hs.WriteTimeout != 0 {
		sc.conn.SetWriteDeadline(time.Time{})
	}

	if s.NewWriteScheduler != nil {
		sc.writeSched = s.NewWriteScheduler()
	} else {
		sc.writeSched = http2newRoundRobinWriteScheduler()
	}

	// These start at the RFC-specified defaults. If there is a higher
	// configured value for inflow, that will be updated when we send a
	// WINDOW_UPDATE shortly after sending SETTINGS.
	sc.flow.add(http2initialWindowSize)
	sc.inflow.init(http2initialWindowSize)
	sc.hpackEncoder = hpack.NewEncoder(&sc.headerWriteBuf)
	sc.hpackEncoder.SetMaxDynamicTableSizeLimit(s.maxEncoderHeaderTableSize())

	fr := http2NewFramer(sc.bw, c)
	if s.CountError != nil {
		fr.countError = s.CountError
	}
	fr.ReadMetaHeaders = hpack.NewDecoder(s.maxDecoderHeaderTableSize(), nil)
	fr.MaxHeaderListSize = sc.maxHeaderListSize()
	fr.SetMaxReadFrameSize(s.maxReadFrameSize())
	sc.framer = fr

	if tc, ok := c.(http2connectionStater); ok {
		sc.tlsState = new(tls.ConnectionState)
		*sc.tlsState = tc.ConnectionState()
		// 9.2 Use of TLS Features
		// An implementation of HTTP/2 over TLS MUST use TLS
		// 1.2 or higher with the restrictions on feature set
		// and cipher suite described in this section. Due to
		// implementation limitations, it might not be
		// possible to fail TLS negotiation. An endpoint MUST
		// immediately terminate an HTTP/2 connection that
		// does not meet the TLS requirements described in
		// this section with a connection error (Section
		// 5.4.1) of type INADEQUATE_SECURITY.
		if sc.tlsState.Version < tls.VersionTLS12 {
			sc.rejectConn(http2ErrCodeInadequateSecurity, "TLS version too low")
			return
		}

		if sc.tlsState.ServerName == "" {
			// Client must use SNI, but we don't enforce that anymore,
			// since it was causing problems when connecting to bare IP
			// addresses during development.
			//
			// TODO: optionally enforce? Or enforce at the time we receive
			// a new request, and verify the ServerName matches the :authority?
			// But that precludes proxy situations, perhaps.
			//
			// So for now, do nothing here again.
		}

		if !s.PermitProhibitedCipherSuites && http2isBadCipher(sc.tlsState.CipherSuite) {
			// "Endpoints MAY choose to generate a connection error
			// (Section 5.4.1) of type INADEQUATE_SECURITY if one of
			// the prohibited cipher suites are negotiated."
			//
			// We choose that. In my opinion, the spec is weak
			// here. It also says both parties must support at least
			// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 so there's no
			// excuses here. If we really must, we could allow an
			// "AllowInsecureWeakCiphers" option on the server later.
			// Let's see how it plays out first.
			sc.rejectConn(http2ErrCodeInadequateSecurity, fmt.Sprintf("Prohibited TLS 1.2 Cipher Suite: %x", sc.tlsState.CipherSuite))
			return
		}
	}

	if opts.Settings != nil {
		fr := &http2SettingsFrame{
			http2FrameHeader: http2FrameHeader{valid: true},
			p:                opts.Settings,
		}
		if err := fr.ForeachSetting(sc.processSetting); err != nil {
			sc.rejectConn(http2ErrCodeProtocol, "invalid settings")
			return
		}
		opts.Settings = nil
	}

	if hook := http2testHookGetServerConn; hook != nil {
		hook(sc)
	}

	if opts.UpgradeRequest != nil {
		sc.upgradeRequest(opts.UpgradeRequest)
		opts.UpgradeRequest = nil
	}

	sc.serve()
}

func http2serverConnBaseContext(c net.Conn, opts *http2ServeConnOpts) (ctx context.Context, cancel func()) {
	ctx, cancel = context.WithCancel(opts.context())
	ctx = context.WithValue(ctx, LocalAddrContextKey, c.LocalAddr())
	if hs := opts.baseConfig(); hs != nil {
		ctx = context.WithValue(ctx, ServerContextKey, hs)
	}
	return
}

func (sc *http2serverConn) rejectConn(err http2ErrCode, debug string) {
	sc.vlogf("http2: server rejecting conn: %v, %s", err, debug)
	// ignoring errors. hanging up anyway.
	sc.framer.WriteGoAway(0, err, []byte(debug))
	sc.bw.Flush()
	sc.conn.Close()
}

type http2serverConn struct {
	// Immutable:
	srv              *http2Server
	hs               *Server
	conn             net.Conn
	bw               *http2bufferedWriter // writing to conn
	handler          http.Handler
	baseCtx          context.Context
	framer           *http2Framer
	doneServing      chan struct{}               // closed when serverConn.serve ends
	readFrameCh      chan http2readFrameResult   // written by serverConn.readFrames
	wantWriteFrameCh chan http2FrameWriteRequest // from handlers -> serve
	wroteFrameCh     chan http2frameWriteResult  // from writeFrameAsync -> serve, tickles more frame writes
	bodyReadCh       chan http2bodyReadMsg       // from handlers -> serve
	serveMsgCh       chan interface{}            // misc messages & code to send to / run on the serve loop
	flow             http2outflow                // conn-wide (not stream-specific) outbound flow control
	inflow           http2inflow                 // conn-wide inbound flow control
	tlsState         *tls.ConnectionState        // shared by all handlers, like net/http
	remoteAddrStr    string
	writeSched       http2WriteScheduler

	// Everything following is owned by the serve loop; use serveG.check():
	serveG                      http2goroutineLock // used to verify funcs are on serve()
	pushEnabled                 bool
	sawClientPreface            bool // preface has already been read, used in h2c upgrade
	sawFirstSettings            bool // got the initial SETTINGS frame after the preface
	needToSendSettingsAck       bool
	unackedSettings             int    // how many SETTINGS have we sent without ACKs?
	queuedControlFrames         int    // control frames in the writeSched queue
	clientMaxStreams            uint32 // SETTINGS_MAX_CONCURRENT_STREAMS from client (our PUSH_PROMISE limit)
	advMaxStreams               uint32 // our SETTINGS_MAX_CONCURRENT_STREAMS advertised the client
	curClientStreams            uint32 // number of open streams initiated by the client
	curPushedStreams            uint32 // number of open streams initiated by server push
	curHandlers                 uint32 // number of running handler goroutines
	maxClientStreamID           uint32 // max ever seen from client (odd), or 0 if there have been no client requests
	maxPushPromiseID            uint32 // ID of the last push promise (even), or 0 if there have been no pushes
	streams                     map[uint32]*http2stream
	unstartedHandlers           []http2unstartedHandler
	initialStreamSendWindowSize int32
	maxFrameSize                int32
	peerMaxHeaderListSize       uint32            // zero means unknown (default)
	canonHeader                 map[string]string // http2-lower-case -> Go-Canonical-Case
	canonHeaderKeysSize         int               // canonHeader keys size in bytes
	writingFrame                bool              // started writing a frame (on serve goroutine or separate)
	writingFrameAsync           bool              // started a frame on its own goroutine but haven't heard back on wroteFrameCh
	needsFrameFlush             bool              // last frame write wasn't a flush
	inGoAway                    bool              // we've started to or sent GOAWAY
	inFrameScheduleLoop         bool              // whether we're in the scheduleFrameWrite loop
	needToSendGoAway            bool              // we need to schedule a GOAWAY frame write
	goAwayCode                  http2ErrCode
	shutdownTimer               *time.Timer // nil until used
	idleTimer                   *time.Timer // nil if unused

	// Owned by the writeFrameAsync goroutine:
	headerWriteBuf bytes.Buffer
	hpackEncoder   *hpack.Encoder

	// Used by startGracefulShutdown.
	shutdownOnce sync.Once
}

func (sc *http2serverConn) maxHeaderListSize() uint32 {
	n := sc.hs.MaxHeaderBytes
	if n <= 0 {
		n = DefaultMaxHeaderBytes
	}
	// http2's count is in a slightly different unit and includes 32 bytes per pair.
	// So, take the net/http.Server value and pad it up a bit, assuming 10 headers.
	const perFieldOverhead = 32 // per http2 spec
	const typicalHeaders = 10   // conservative
	return uint32(n + typicalHeaders*perFieldOverhead)
}

func (sc *http2serverConn) curOpenStreams() uint32 {
	sc.serveG.check()
	return sc.curClientStreams + sc.curPushedStreams
}

// stream represents a stream. This is the minimal metadata needed by
// the serve goroutine. Most of the actual stream state is owned by
// the http.Handler's goroutine in the responseWriter. Because the
// responseWriter's responseWriterState is recycled at the end of a
// handler, this struct intentionally has no pointer to the
// *responseWriter{,State} itself, as the Handler ending nils out the
// responseWriter's state field.
type http2stream struct {
	// immutable:
	sc        *http2serverConn
	id        uint32
	body      *http2pipe       // non-nil if expecting DATA frames
	cw        http2closeWaiter // closed wait stream transitions to closed state
	ctx       context.Context
	cancelCtx func()

	// owned by serverConn's serve loop:
	bodyBytes        int64        // body bytes seen so far
	declBodyBytes    int64        // or -1 if undeclared
	flow             http2outflow // limits writing from Handler to client
	inflow           http2inflow  // what the client is allowed to POST/etc to us
	state            http2streamState
	resetQueued      bool        // RST_STREAM queued for write; set by sc.resetStream
	gotTrailerHeader bool        // HEADER frame for trailers was seen
	wroteHeaders     bool        // whether we wrote headers (not status 100)
	readDeadline     *time.Timer // nil if unused
	writeDeadline    *time.Timer // nil if unused
	closeErr         error       // set before cw is closed

	trailer    http.Header // accumulated trailers
	reqTrailer http.Header // handler's Request.Trailer
}

func (sc *http2serverConn) Framer() *http2Framer { return sc.framer }

func (sc *http2serverConn) CloseConn() error { return sc.conn.Close() }

func (sc *http2serverConn) Flush() error { return sc.bw.Flush() }

func (sc *http2serverConn) HeaderEncoder() (*hpack.Encoder, *bytes.Buffer) {
	return sc.hpackEncoder, &sc.headerWriteBuf
}

func (sc *http2serverConn) state(streamID uint32) (http2streamState, *http2stream) {
	sc.serveG.check()
	// http://tools.ietf.org/html/rfc7540#section-5.1
	if st, ok := sc.streams[streamID]; ok {
		return st.state, st
	}
	// "The first use of a new stream identifier implicitly closes all
	// streams in the "idle" state that might have been initiated by
	// that peer with a lower-valued stream identifier. For example, if
	// a client sends a HEADERS frame on stream 7 without ever sending a
	// frame on stream 5, then stream 5 transitions to the "closed"
	// state when the first frame for stream 7 is sent or received."
	if streamID%2 == 1 {
		if streamID <= sc.maxClientStreamID {
			return http2stateClosed, nil
		}
	} else {
		if streamID <= sc.maxPushPromiseID {
			return http2stateClosed, nil
		}
	}
	return http2stateIdle, nil
}

// setConnState calls the net/http ConnState hook for this connection, if configured.
// Note that the net/http package does StateNew and StateClosed for us.
// There is currently no plan for StateHijacked or hijacking HTTP/2 connections.
func (sc *http2serverConn) setConnState(state http.ConnState) {
	if sc.hs.ConnState != nil {
		sc.hs.ConnState(sc.conn, state)
	}
}

func (sc *http2serverConn) vlogf(format string, args ...interface{}) {
	if http2VerboseLogs {
		sc.logf(format, args...)
	}
}

func (sc *http2serverConn) logf(format string, args ...interface{}) {
	if lg := sc.hs.ErrorLog; lg != nil {
		lg.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// errno returns v's underlying uintptr, else 0.
//
// TODO: remove this helper function once http2 can use build
// tags. See comment in isClosedConnError.
func http2errno(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

// isClosedConnError reports whether err is an error from use of a closed
// network connection.
func http2isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	// TODO: remove this string search and be more like the Windows
	// case below. That might involve modifying the standard library
	// to return better error types.
	str := err.Error()
	if strings.Contains(str, "use of closed network connection") {
		return true
	}

	// TODO(bradfitz): x/tools/cmd/bundle doesn't really support
	// build tags, so I can't make an http2_windows.go file with
	// Windows-specific stuff. Fix that and move this, once we
	// have a way to bundle this into std's net/http somehow.
	if runtime.GOOS == "windows" {
		if oe, ok := err.(*net.OpError); ok && oe.Op == "read" {
			if se, ok := oe.Err.(*os.SyscallError); ok && se.Syscall == "wsarecv" {
				const WSAECONNABORTED = 10053
				const WSAECONNRESET = 10054
				if n := http2errno(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
					return true
				}
			}
		}
	}
	return false
}

func (sc *http2serverConn) condlogf(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF || http2isClosedConnError(err) || err == http2errPrefaceTimeout {
		// Boring, expected errors.
		sc.vlogf(format, args...)
	} else {
		sc.logf(format, args...)
	}
}

// maxCachedCanonicalHeadersKeysSize is an arbitrarily-chosen limit on the size
// of the entries in the canonHeader cache.
// This should be larger than the size of unique, uncommon header keys likely to
// be sent by the peer, while not so high as to permit unreasonable memory usage
// if the peer sends an unbounded number of unique header keys.
const http2maxCachedCanonicalHeadersKeysSize = 2048

func (sc *http2serverConn) canonicalHeader(v string) string {
	sc.serveG.check()
	http2buildCommonHeaderMapsOnce()
	cv, ok := http2commonCanonHeader[v]
	if ok {
		return cv
	}
	cv, ok = sc.canonHeader[v]
	if ok {
		return cv
	}
	if sc.canonHeader == nil {
		sc.canonHeader = make(map[string]string)
	}
	cv = http.CanonicalHeaderKey(v)
	size := 100 + len(v)*2 // 100 bytes of map overhead + key + value
	if sc.canonHeaderKeysSize+size <= http2maxCachedCanonicalHeadersKeysSize {
		sc.canonHeader[v] = cv
		sc.canonHeaderKeysSize += size
	}
	return cv
}

type http2readFrameResult struct {
	f   http2Frame // valid until readMore is called
	err error

	// readMore should be called once the consumer no longer needs or
	// retains f. After readMore, f is invalid and more frames can be
	// read.
	readMore func()
}

// readFrames is the loop that reads incoming frames.
// It takes care to only read one frame at a time, blocking until the
// consumer is done with the frame.
// It's run on its own goroutine.
func (sc *http2serverConn) readFrames() {
	gate := make(http2gate)
	gateDone := gate.Done
	for {
		f, err := sc.framer.ReadFrame()
		select {
		case sc.readFrameCh <- http2readFrameResult{f, err, gateDone}:
		case <-sc.doneServing:
			return
		}
		select {
		case <-gate:
		case <-sc.doneServing:
			return
		}
		if http2terminalReadFrameError(err) {
			return
		}
	}
}

// frameWriteResult is the message passed from writeFrameAsync to the serve goroutine.
type http2frameWriteResult struct {
	_   http2incomparable
	wr  http2FrameWriteRequest // what was written (or attempted)
	err error                  // result of the writeFrame call
}

// writeFrameAsync runs in its own goroutine and writes a single frame
// and then reports when it's done.
// At most one goroutine can be running writeFrameAsync at a time per
// serverConn.
func (sc *http2serverConn) writeFrameAsync(wr http2FrameWriteRequest, wd *http2writeData) {
	var err error
	if wd == nil {
		err = wr.write.writeFrame(sc)
	} else {
		err = sc.framer.endWrite()
	}
	sc.wroteFrameCh <- http2frameWriteResult{wr: wr, err: err}
}

func (sc *http2serverConn) closeAllStreamsOnConnClose() {
	sc.serveG.check()
	for _, st := range sc.streams {
		sc.closeStream(st, http2errClientDisconnected)
	}
}

func (sc *http2serverConn) stopShutdownTimer() {
	sc.serveG.check()
	if t := sc.shutdownTimer; t != nil {
		t.Stop()
	}
}

func (sc *http2serverConn) notePanic() {
	// Note: this is for serverConn.serve panicking, not http.Handler code.
	if http2testHookOnPanicMu != nil {
		http2testHookOnPanicMu.Lock()
		defer http2testHookOnPanicMu.Unlock()
	}
	if http2testHookOnPanic != nil {
		if e := recover(); e != nil {
			if http2testHookOnPanic(sc, e) {
				panic(e)
			}
		}
	}
}

func (sc *http2serverConn) serve() {
	sc.serveG.check()
	defer sc.notePanic()
	defer sc.conn.Close()
	defer sc.closeAllStreamsOnConnClose()
	defer sc.stopShutdownTimer()
	defer close(sc.doneServing) // unblocks handlers trying to send

	if http2VerboseLogs {
		sc.vlogf("http2: server connection from %v on %p", sc.conn.RemoteAddr(), sc.hs)
	}

	sc.writeFrame(http2FrameWriteRequest{
		write: http2writeSettings{
			{http2SettingMaxFrameSize, sc.srv.maxReadFrameSize()},
			{http2SettingMaxConcurrentStreams, sc.advMaxStreams},
			{http2SettingMaxHeaderListSize, sc.maxHeaderListSize()},
			{http2SettingHeaderTableSize, sc.srv.maxDecoderHeaderTableSize()},
			{http2SettingInitialWindowSize, uint32(sc.srv.initialStreamRecvWindowSize())},
		},
	})
	sc.unackedSettings++

	// Each connection starts with initialWindowSize inflow tokens.
	// If a higher value is configured, we add more tokens.
	if diff := sc.srv.initialConnRecvWindowSize() - http2initialWindowSize; diff > 0 {
		sc.sendWindowUpdate(nil, int(diff))
	}

	if err := sc.readPreface(); err != nil {
		sc.condlogf(err, "http2: server: error reading preface from client %v: %v", sc.conn.RemoteAddr(), err)
		return
	}
	// Now that we've got the preface, get us out of the
	// "StateNew" state. We can't go directly to idle, though.
	// Active means we read some data and anticipate a request. We'll
	// do another Active when we get a HEADERS frame.
	sc.setConnState(http.StateActive)
	sc.setConnState(http.StateIdle)

	if sc.srv.IdleTimeout != 0 {
		sc.idleTimer = time.AfterFunc(sc.srv.IdleTimeout, sc.onIdleTimer)
		defer sc.idleTimer.Stop()
	}

	go sc.readFrames() // closed by defer sc.conn.Close above

	settingsTimer := time.AfterFunc(http2firstSettingsTimeout, sc.onSettingsTimer)
	defer settingsTimer.Stop()

	loopNum := 0
	for {
		loopNum++
		select {
		case wr := <-sc.wantWriteFrameCh:
			if se, ok := wr.write.(http2StreamError); ok {
				sc.resetStream(se)
				break
			}
			sc.writeFrame(wr)
		case res := <-sc.wroteFrameCh:
			sc.wroteFrame(res)
		case res := <-sc.readFrameCh:
			// Process any written frames before reading new frames from the client since a
			// written frame could have triggered a new stream to be started.
			if sc.writingFrameAsync {
				select {
				case wroteRes := <-sc.wroteFrameCh:
					sc.wroteFrame(wroteRes)
				default:
				}
			}
			if !sc.processFrameFromReader(res) {
				return
			}
			res.readMore()
			if settingsTimer != nil {
				settingsTimer.Stop()
				settingsTimer = nil
			}
		case m := <-sc.bodyReadCh:
			sc.noteBodyRead(m.st, m.n)
		case msg := <-sc.serveMsgCh:
			switch v := msg.(type) {
			case func(int):
				v(loopNum) // for testing
			case *http2serverMessage:
				switch v {
				case http2settingsTimerMsg:
					sc.logf("timeout waiting for SETTINGS frames from %v", sc.conn.RemoteAddr())
					return
				case http2idleTimerMsg:
					sc.vlogf("connection is idle")
					sc.goAway(http2ErrCodeNo)
				case http2shutdownTimerMsg:
					sc.vlogf("GOAWAY close timer fired; closing conn from %v", sc.conn.RemoteAddr())
					return
				case http2gracefulShutdownMsg:
					sc.startGracefulShutdownInternal()
				case http2handlerDoneMsg:
					sc.handlerDone()
				default:
					panic("unknown timer")
				}
			case *http2startPushRequest:
				sc.startPush(v)
			case func(*http2serverConn):
				v(sc)
			default:
				panic(fmt.Sprintf("unexpected type %T", v))
			}
		}

		// If the peer is causing us to generate a lot of control frames,
		// but not reading them from us, assume they are trying to make us
		// run out of memory.
		if sc.queuedControlFrames > sc.srv.maxQueuedControlFrames() {
			sc.vlogf("http2: too many control frames in send queue, closing connection")
			return
		}

		// Start the shutdown timer after sending a GOAWAY. When sending GOAWAY
		// with no error code (graceful shutdown), don't start the timer until
		// all open streams have been completed.
		sentGoAway := sc.inGoAway && !sc.needToSendGoAway && !sc.writingFrame
		gracefulShutdownComplete := sc.goAwayCode == http2ErrCodeNo && sc.curOpenStreams() == 0
		if sentGoAway && sc.shutdownTimer == nil && (sc.goAwayCode != http2ErrCodeNo || gracefulShutdownComplete) {
			sc.shutDownIn(http2goAwayTimeout)
		}
	}
}

func (sc *http2serverConn) awaitGracefulShutdown(sharedCh <-chan struct{}, privateCh chan struct{}) {
	select {
	case <-sc.doneServing:
	case <-sharedCh:
		close(privateCh)
	}
}

type http2serverMessage int

// Message values sent to serveMsgCh.
var (
	http2settingsTimerMsg    = new(http2serverMessage)
	http2idleTimerMsg        = new(http2serverMessage)
	http2shutdownTimerMsg    = new(http2serverMessage)
	http2gracefulShutdownMsg = new(http2serverMessage)
	http2handlerDoneMsg      = new(http2serverMessage)
)

func (sc *http2serverConn) onSettingsTimer() { sc.sendServeMsg(http2settingsTimerMsg) }

func (sc *http2serverConn) onIdleTimer() { sc.sendServeMsg(http2idleTimerMsg) }

func (sc *http2serverConn) onShutdownTimer() { sc.sendServeMsg(http2shutdownTimerMsg) }

func (sc *http2serverConn) sendServeMsg(msg interface{}) {
	sc.serveG.checkNotOn() // NOT
	select {
	case sc.serveMsgCh <- msg:
	case <-sc.doneServing:
	}
}

var http2errPrefaceTimeout = errors.New("timeout waiting for client preface")

// readPreface reads the ClientPreface greeting from the peer or
// returns errPrefaceTimeout on timeout, or an error if the greeting
// is invalid.
func (sc *http2serverConn) readPreface() error {
	if sc.sawClientPreface {
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		// Read the client preface
		buf := make([]byte, len(http2ClientPreface))
		if _, err := io.ReadFull(sc.conn, buf); err != nil {
			errc <- err
		} else if !bytes.Equal(buf, http2clientPreface) {
			errc <- fmt.Errorf("bogus greeting %q", buf)
		} else {
			errc <- nil
		}
	}()
	timer := time.NewTimer(http2prefaceTimeout) // TODO: configurable on *Server?
	defer timer.Stop()
	select {
	case <-timer.C:
		return http2errPrefaceTimeout
	case err := <-errc:
		if err == nil {
			if http2VerboseLogs {
				sc.vlogf("http2: server: client %v said hello", sc.conn.RemoteAddr())
			}
		}
		return err
	}
}

var http2errChanPool = sync.Pool{
	New: func() interface{} { return make(chan error, 1) },
}

var http2writeDataPool = sync.Pool{
	New: func() interface{} { return new(http2writeData) },
}

// writeDataFromHandler writes DATA response frames from a handler on
// the given stream.
func (sc *http2serverConn) writeDataFromHandler(stream *http2stream, data []byte, endStream bool) error {
	ch := http2errChanPool.Get().(chan error)
	writeArg := http2writeDataPool.Get().(*http2writeData)
	*writeArg = http2writeData{stream.id, data, endStream}
	err := sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  writeArg,
		stream: stream,
		done:   ch,
	})
	if err != nil {
		return err
	}
	var frameWriteDone bool // the frame write is done (successfully or not)
	select {
	case err = <-ch:
		frameWriteDone = true
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-stream.cw:
		// If both ch and stream.cw were ready (as might
		// happen on the final Write after an http.Handler
		// ends), prefer the write result. Otherwise this
		// might just be us successfully closing the stream.
		// The writeFrameAsync and serve goroutines guarantee
		// that the ch send will happen before the stream.cw
		// close.
		select {
		case err = <-ch:
			frameWriteDone = true
		default:
			return http2errStreamClosed
		}
	}
	http2errChanPool.Put(ch)
	if frameWriteDone {
		http2writeDataPool.Put(writeArg)
	}
	return err
}

// writeFrameFromHandler sends wr to sc.wantWriteFrameCh, but aborts
// if the connection has gone away.
//
// This must not be run from the serve goroutine itself, else it might
// deadlock writing to sc.wantWriteFrameCh (which is only mildly
// buffered and is read by serve itself). If you're on the serve
// goroutine, call writeFrame instead.
func (sc *http2serverConn) writeFrameFromHandler(wr http2FrameWriteRequest) error {
	sc.serveG.checkNotOn() // NOT
	select {
	case sc.wantWriteFrameCh <- wr:
		return nil
	case <-sc.doneServing:
		// Serve loop is gone.
		// Client has closed their connection to the server.
		return http2errClientDisconnected
	}
}

// writeFrame schedules a frame to write and sends it if there's nothing
// already being written.
//
// There is no pushback here (the serve goroutine never blocks). It's
// the http.Handlers that block, waiting for their previous frames to
// make it onto the wire
//
// If you're not on the serve goroutine, use writeFrameFromHandler instead.
func (sc *http2serverConn) writeFrame(wr http2FrameWriteRequest) {
	sc.serveG.check()

	// If true, wr will not be written and wr.done will not be signaled.
	var ignoreWrite bool

	// We are not allowed to write frames on closed streams. RFC 7540 Section
	// 5.1.1 says: "An endpoint MUST NOT send frames other than PRIORITY on
	// a closed stream." Our server never sends PRIORITY, so that exception
	// does not apply.
	//
	// The serverConn might close an open stream while the stream's handler
	// is still running. For example, the server might close a stream when it
	// receives bad data from the client. If this happens, the handler might
	// attempt to write a frame after the stream has been closed (since the
	// handler hasn't yet been notified of the close). In this case, we simply
	// ignore the frame. The handler will notice that the stream is closed when
	// it waits for the frame to be written.
	//
	// As an exception to this rule, we allow sending RST_STREAM after close.
	// This allows us to immediately reject new streams without tracking any
	// state for those streams (except for the queued RST_STREAM frame). This
	// may result in duplicate RST_STREAMs in some cases, but the client should
	// ignore those.
	if wr.StreamID() != 0 {
		_, isReset := wr.write.(http2StreamError)
		if state, _ := sc.state(wr.StreamID()); state == http2stateClosed && !isReset {
			ignoreWrite = true
		}
	}

	// Don't send a 100-continue response if we've already sent headers.
	// See golang.org/issue/14030.
	switch wr.write.(type) {
	case *http2writeResHeaders:
		wr.stream.wroteHeaders = true
	case http2write100ContinueHeadersFrame:
		if wr.stream.wroteHeaders {
			// We do not need to notify wr.done because this frame is
			// never written with wr.done != nil.
			if wr.done != nil {
				panic("wr.done != nil for write100ContinueHeadersFrame")
			}
			ignoreWrite = true
		}
	}

	if !ignoreWrite {
		if wr.isControl() {
			sc.queuedControlFrames++
			// For extra safety, detect wraparounds, which should not happen,
			// and pull the plug.
			if sc.queuedControlFrames < 0 {
				sc.conn.Close()
			}
		}
		sc.writeSched.Push(wr)
	}
	sc.scheduleFrameWrite()
}

// startFrameWrite starts a goroutine to write wr (in a separate
// goroutine since that might block on the network), and updates the
// serve goroutine's state about the world, updated from info in wr.
func (sc *http2serverConn) startFrameWrite(wr http2FrameWriteRequest) {
	sc.serveG.check()
	if sc.writingFrame {
		panic("internal error: can only be writing one frame at a time")
	}

	st := wr.stream
	if st != nil {
		switch st.state {
		case http2stateHalfClosedLocal:
			switch wr.write.(type) {
			case http2StreamError, http2handlerPanicRST, http2writeWindowUpdate:
				// RFC 7540 Section 5.1 allows sending RST_STREAM, PRIORITY, and WINDOW_UPDATE
				// in this state. (We never send PRIORITY from the server, so that is not checked.)
			default:
				panic(fmt.Sprintf("internal error: attempt to send frame on a half-closed-local stream: %v", wr))
			}
		case http2stateClosed:
			panic(fmt.Sprintf("internal error: attempt to send frame on a closed stream: %v", wr))
		}
	}
	if wpp, ok := wr.write.(*http2writePushPromise); ok {
		var err error
		wpp.promisedID, err = wpp.allocatePromisedID()
		if err != nil {
			sc.writingFrameAsync = false
			wr.replyToWriter(err)
			return
		}
	}

	sc.writingFrame = true
	sc.needsFrameFlush = true
	if wr.write.staysWithinBuffer(sc.bw.Available()) {
		sc.writingFrameAsync = false
		err := wr.write.writeFrame(sc)
		sc.wroteFrame(http2frameWriteResult{wr: wr, err: err})
	} else if wd, ok := wr.write.(*http2writeData); ok {
		// Encode the frame in the serve goroutine, to ensure we don't have
		// any lingering asynchronous references to data passed to Write.
		// See https://go.dev/issue/58446.
		sc.framer.startWriteDataPadded(wd.streamID, wd.endStream, wd.p, nil)
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, wd)
	} else {
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, nil)
	}
}

// errHandlerPanicked is the error given to any callers blocked in a read from
// Request.Body when the main goroutine panics. Since most handlers read in the
// main ServeHTTP goroutine, this will show up rarely.
var http2errHandlerPanicked = errors.New("http2: handler panicked")

// wroteFrame is called on the serve goroutine with the result of
// whatever happened on writeFrameAsync.
func (sc *http2serverConn) wroteFrame(res http2frameWriteResult) {
	sc.serveG.check()
	if !sc.writingFrame {
		panic("internal error: expected to be already writing a frame")
	}
	sc.writingFrame = false
	sc.writingFrameAsync = false

	wr := res.wr

	if http2writeEndsStream(wr.write) {
		st := wr.stream
		if st == nil {
			panic("internal error: expecting non-nil stream")
		}
		switch st.state {
		case http2stateOpen:
			// Here we would go to stateHalfClosedLocal in
			// theory, but since our handler is done and
			// the net/http package provides no mechanism
			// for closing a ResponseWriter while still
			// reading data (see possible TODO at top of
			// this file), we go into closed state here
			// anyway, after telling the peer we're
			// hanging up on them. We'll transition to
			// stateClosed after the RST_STREAM frame is
			// written.
			st.state = http2stateHalfClosedLocal
			// Section 8.1: a server MAY request that the client abort
			// transmission of a request without error by sending a
			// RST_STREAM with an error code of NO_ERROR after sending
			// a complete response.
			sc.resetStream(http2streamError(st.id, http2ErrCodeNo))
		case http2stateHalfClosedRemote:
			sc.closeStream(st, http2errHandlerComplete)
		}
	} else {
		switch v := wr.write.(type) {
		case http2StreamError:
			// st may be unknown if the RST_STREAM was generated to reject bad input.
			if st, ok := sc.streams[v.StreamID]; ok {
				sc.closeStream(st, v)
			}
		case http2handlerPanicRST:
			sc.closeStream(wr.stream, http2errHandlerPanicked)
		}
	}

	// Reply (if requested) to unblock the ServeHTTP goroutine.
	wr.replyToWriter(res.err)

	sc.scheduleFrameWrite()
}

// scheduleFrameWrite tickles the frame writing scheduler.
//
// If a frame is already being written, nothing happens. This will be called again
// when the frame is done being written.
//
// If a frame isn't being written and we need to send one, the best frame
// to send is selected by writeSched.
//
// If a frame isn't being written and there's nothing else to send, we
// flush the write buffer.
func (sc *http2serverConn) scheduleFrameWrite() {
	sc.serveG.check()
	if sc.writingFrame || sc.inFrameScheduleLoop {
		return
	}
	sc.inFrameScheduleLoop = true
	for !sc.writingFrameAsync {
		if sc.needToSendGoAway {
			sc.needToSendGoAway = false
			sc.startFrameWrite(http2FrameWriteRequest{
				write: &http2writeGoAway{
					maxStreamID: sc.maxClientStreamID,
					code:        sc.goAwayCode,
				},
			})
			continue
		}
		if sc.needToSendSettingsAck {
			sc.needToSendSettingsAck = false
			sc.startFrameWrite(http2FrameWriteRequest{write: http2writeSettingsAck{}})
			continue
		}
		if !sc.inGoAway || sc.goAwayCode == http2ErrCodeNo {
			if wr, ok := sc.writeSched.Pop(); ok {
				if wr.isControl() {
					sc.queuedControlFrames--
				}
				sc.startFrameWrite(wr)
				continue
			}
		}
		if sc.needsFrameFlush {
			sc.startFrameWrite(http2FrameWriteRequest{write: http2flushFrameWriter{}})
			sc.needsFrameFlush = false // after startFrameWrite, since it sets this true
			continue
		}
		break
	}
	sc.inFrameScheduleLoop = false
}

// startGracefulShutdown gracefully shuts down a connection. This
// sends GOAWAY with ErrCodeNo to tell the client we're gracefully
// shutting down. The connection isn't closed until all current
// streams are done.
//
// startGracefulShutdown returns immediately; it does not wait until
// the connection has shut down.
func (sc *http2serverConn) startGracefulShutdown() {
	sc.serveG.checkNotOn() // NOT
	sc.shutdownOnce.Do(func() { sc.sendServeMsg(http2gracefulShutdownMsg) })
}

// After sending GOAWAY with an error code (non-graceful shutdown), the
// connection will close after goAwayTimeout.
//
// If we close the connection immediately after sending GOAWAY, there may
// be unsent data in our kernel receive buffer, which will cause the kernel
// to send a TCP RST on close() instead of a FIN. This RST will abort the
// connection immediately, whether or not the client had received the GOAWAY.
//
// Ideally we should delay for at least 1 RTT + epsilon so the client has
// a chance to read the GOAWAY and stop sending messages. Measuring RTT
// is hard, so we approximate with 1 second. See golang.org/issue/18701.
//
// This is a var so it can be shorter in tests, where all requests uses the
// loopback interface making the expected RTT very small.
//
// TODO: configurable?
var http2goAwayTimeout = 1 * time.Second

func (sc *http2serverConn) startGracefulShutdownInternal() {
	sc.goAway(http2ErrCodeNo)
}

func (sc *http2serverConn) goAway(code http2ErrCode) {
	sc.serveG.check()
	if sc.inGoAway {
		if sc.goAwayCode == http2ErrCodeNo {
			sc.goAwayCode = code
		}
		return
	}
	sc.inGoAway = true
	sc.needToSendGoAway = true
	sc.goAwayCode = code
	sc.scheduleFrameWrite()
}

func (sc *http2serverConn) shutDownIn(d time.Duration) {
	sc.serveG.check()
	sc.shutdownTimer = time.AfterFunc(d, sc.onShutdownTimer)
}

func (sc *http2serverConn) resetStream(se http2StreamError) {
	sc.serveG.check()
	sc.writeFrame(http2FrameWriteRequest{write: se})
	if st, ok := sc.streams[se.StreamID]; ok {
		st.resetQueued = true
	}
}

// processFrameFromReader processes the serve loop's read from readFrameCh from the
// frame-reading goroutine.
// processFrameFromReader returns whether the connection should be kept open.
func (sc *http2serverConn) processFrameFromReader(res http2readFrameResult) bool {
	sc.serveG.check()
	err := res.err
	if err != nil {
		if err == http2ErrFrameTooLarge {
			sc.goAway(http2ErrCodeFrameSize)
			return true // goAway will close the loop
		}
		clientGone := err == io.EOF || err == io.ErrUnexpectedEOF || http2isClosedConnError(err)
		if clientGone {
			// TODO: could we also get into this state if
			// the peer does a half close
			// (e.g. CloseWrite) because they're done
			// sending frames but they're still wanting
			// our open replies?  Investigate.
			// TODO: add CloseWrite to crypto/tls.Conn first
			// so we have a way to test this? I suppose
			// just for testing we could have a non-TLS mode.
			return false
		}
	} else {
		f := res.f
		if http2VerboseLogs {
			sc.vlogf("http2: server read frame %v", http2summarizeFrame(f))
		}
		err = sc.processFrame(f)
		if err == nil {
			return true
		}
	}

	switch ev := err.(type) {
	case http2StreamError:
		sc.resetStream(ev)
		return true
	case http2goAwayFlowError:
		sc.goAway(http2ErrCodeFlowControl)
		return true
	case http2ConnectionError:
		sc.logf("http2: server connection error from %v: %v", sc.conn.RemoteAddr(), ev)
		sc.goAway(http2ErrCode(ev))
		return true // goAway will handle shutdown
	default:
		if res.err != nil {
			sc.vlogf("http2: server closing client connection; error reading frame from client %s: %v", sc.conn.RemoteAddr(), err)
		} else {
			sc.logf("http2: server closing client connection: %v", err)
		}
		return false
	}
}

func (sc *http2serverConn) processFrame(f http2Frame) error {
	sc.serveG.check()

	// First frame received must be SETTINGS.
	if !sc.sawFirstSettings {
		if _, ok := f.(*http2SettingsFrame); !ok {
			return sc.countError("first_settings", http2ConnectionError(http2ErrCodeProtocol))
		}
		sc.sawFirstSettings = true
	}

	// Discard frames for streams initiated after the identified last
	// stream sent in a GOAWAY, or all frames after sending an error.
	// We still need to return connection-level flow control for DATA frames.
	// RFC 9113 Section 6.8.
	if sc.inGoAway && (sc.goAwayCode != http2ErrCodeNo || f.Header().StreamID > sc.maxClientStreamID) {

		if f, ok := f.(*http2DataFrame); ok {
			if !sc.inflow.take(f.Length) {
				return sc.countError("data_flow", http2streamError(f.Header().StreamID, http2ErrCodeFlowControl))
			}
			sc.sendWindowUpdate(nil, int(f.Length)) // conn-level
		}
		return nil
	}

	switch f := f.(type) {
	case *http2SettingsFrame:
		return sc.processSettings(f)
	case *http2MetaHeadersFrame:
		return sc.processHeaders(f)
	case *http2WindowUpdateFrame:
		return sc.processWindowUpdate(f)
	case *http2PingFrame:
		return sc.processPing(f)
	case *http2DataFrame:
		return sc.processData(f)
	case *http2RSTStreamFrame:
		return sc.processResetStream(f)
	case *http2PriorityFrame:
		return sc.processPriority(f)
	case *http2GoAwayFrame:
		return sc.processGoAway(f)
	case *http2PushPromiseFrame:
		// A client cannot push. Thus, servers MUST treat the receipt of a PUSH_PROMISE
		// frame as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
		return sc.countError("push_promise", http2ConnectionError(http2ErrCodeProtocol))
	default:
		sc.vlogf("http2: server ignoring frame: %v", f.Header())
		return nil
	}
}

func (sc *http2serverConn) processPing(f *http2PingFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		// 6.7 PING: " An endpoint MUST NOT respond to PING frames
		// containing this flag."
		return nil
	}
	if f.StreamID != 0 {
		// "PING frames are not associated with any individual
		// stream. If a PING frame is received with a stream
		// identifier field value other than 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR."
		return sc.countError("ping_on_stream", http2ConnectionError(http2ErrCodeProtocol))
	}
	sc.writeFrame(http2FrameWriteRequest{write: http2writePingAck{f}})
	return nil
}

func (sc *http2serverConn) processWindowUpdate(f *http2WindowUpdateFrame) error {
	sc.serveG.check()
	switch {
	case f.StreamID != 0: // stream-level flow control
		state, st := sc.state(f.StreamID)
		if state == http2stateIdle {
			// Section 5.1: "Receiving any frame other than HEADERS
			// or PRIORITY on a stream in this state MUST be
			// treated as a connection error (Section 5.4.1) of
			// type PROTOCOL_ERROR."
			return sc.countError("stream_idle", http2ConnectionError(http2ErrCodeProtocol))
		}
		if st == nil {
			// "WINDOW_UPDATE can be sent by a peer that has sent a
			// frame bearing the END_STREAM flag. This means that a
			// receiver could receive a WINDOW_UPDATE frame on a "half
			// closed (remote)" or "closed" stream. A receiver MUST
			// NOT treat this as an error, see Section 5.1."
			return nil
		}
		if !st.flow.add(int32(f.Increment)) {
			return sc.countError("bad_flow", http2streamError(f.StreamID, http2ErrCodeFlowControl))
		}
	default: // connection-level flow control
		if !sc.flow.add(int32(f.Increment)) {
			return http2goAwayFlowError{}
		}
	}
	sc.scheduleFrameWrite()
	return nil
}

func (sc *http2serverConn) processResetStream(f *http2RSTStreamFrame) error {
	sc.serveG.check()

	state, st := sc.state(f.StreamID)
	if state == http2stateIdle {
		// 6.4 "RST_STREAM frames MUST NOT be sent for a
		// stream in the "idle" state. If a RST_STREAM frame
		// identifying an idle stream is received, the
		// recipient MUST treat this as a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		return sc.countError("reset_idle_stream", http2ConnectionError(http2ErrCodeProtocol))
	}
	if st != nil {
		st.cancelCtx()
		sc.closeStream(st, http2streamError(f.StreamID, f.ErrCode))
	}
	return nil
}

func (sc *http2serverConn) closeStream(st *http2stream, err error) {
	sc.serveG.check()
	if st.state == http2stateIdle || st.state == http2stateClosed {
		panic(fmt.Sprintf("invariant; can't close stream in state %v", st.state))
	}
	st.state = http2stateClosed
	if st.readDeadline != nil {
		st.readDeadline.Stop()
	}
	if st.writeDeadline != nil {
		st.writeDeadline.Stop()
	}
	if st.isPushed() {
		sc.curPushedStreams--
	} else {
		sc.curClientStreams--
	}
	delete(sc.streams, st.id)
	if len(sc.streams) == 0 {
		sc.setConnState(http.StateIdle)
		if sc.srv.IdleTimeout != 0 {
			sc.idleTimer.Reset(sc.srv.IdleTimeout)
		}
		if http2h1ServerKeepAlivesDisabled(sc.hs) {
			sc.startGracefulShutdownInternal()
		}
	}
	if p := st.body; p != nil {
		// Return any buffered unread bytes worth of conn-level flow control.
		// See golang.org/issue/16481
		sc.sendWindowUpdate(nil, p.Len())

		p.CloseWithError(err)
	}
	if e, ok := err.(http2StreamError); ok {
		if e.Cause != nil {
			err = e.Cause
		} else {
			err = http2errStreamClosed
		}
	}
	st.closeErr = err
	st.cw.Close() // signals Handler's CloseNotifier, unblocks writes, etc
	sc.writeSched.CloseStream(st.id)
}

func (sc *http2serverConn) processSettings(f *http2SettingsFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		sc.unackedSettings--
		if sc.unackedSettings < 0 {
			// Why is the peer ACKing settings we never sent?
			// The spec doesn't mention this case, but
			// hang up on them anyway.
			return sc.countError("ack_mystery", http2ConnectionError(http2ErrCodeProtocol))
		}
		return nil
	}
	if f.NumSettings() > 100 || f.HasDuplicates() {
		// This isn't actually in the spec, but hang up on
		// suspiciously large settings frames or those with
		// duplicate entries.
		return sc.countError("settings_big_or_dups", http2ConnectionError(http2ErrCodeProtocol))
	}
	if err := f.ForeachSetting(sc.processSetting); err != nil {
		return err
	}
	// TODO: judging by RFC 7540, Section 6.5.3 each SETTINGS frame should be
	// acknowledged individually, even if multiple are received before the ACK.
	sc.needToSendSettingsAck = true
	sc.scheduleFrameWrite()
	return nil
}

func (sc *http2serverConn) processSetting(s http2Setting) error {
	sc.serveG.check()
	if err := s.Valid(); err != nil {
		return err
	}
	if http2VerboseLogs {
		sc.vlogf("http2: server processing setting %v", s)
	}
	switch s.ID {
	case http2SettingHeaderTableSize:
		sc.hpackEncoder.SetMaxDynamicTableSize(s.Val)
	case http2SettingEnablePush:
		sc.pushEnabled = s.Val != 0
	case http2SettingMaxConcurrentStreams:
		sc.clientMaxStreams = s.Val
	case http2SettingInitialWindowSize:
		return sc.processSettingInitialWindowSize(s.Val)
	case http2SettingMaxFrameSize:
		sc.maxFrameSize = int32(s.Val) // the maximum valid s.Val is < 2^31
	case http2SettingMaxHeaderListSize:
		sc.peerMaxHeaderListSize = s.Val
	default:
		// Unknown setting: "An endpoint that receives a SETTINGS
		// frame with any unknown or unsupported identifier MUST
		// ignore that setting."
		if http2VerboseLogs {
			sc.vlogf("http2: server ignoring unknown setting %v", s)
		}
	}
	return nil
}

func (sc *http2serverConn) processSettingInitialWindowSize(val uint32) error {
	sc.serveG.check()
	// Note: val already validated to be within range by
	// processSetting's Valid call.

	// "A SETTINGS frame can alter the initial flow control window
	// size for all current streams. When the value of
	// SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST
	// adjust the size of all stream flow control windows that it
	// maintains by the difference between the new value and the
	// old value."
	old := sc.initialStreamSendWindowSize
	sc.initialStreamSendWindowSize = int32(val)
	growth := int32(val) - old // may be negative
	for _, st := range sc.streams {
		if !st.flow.add(growth) {
			// 6.9.2 Initial Flow Control Window Size
			// "An endpoint MUST treat a change to
			// SETTINGS_INITIAL_WINDOW_SIZE that causes any flow
			// control window to exceed the maximum size as a
			// connection error (Section 5.4.1) of type
			// FLOW_CONTROL_ERROR."
			return sc.countError("setting_win_size", http2ConnectionError(http2ErrCodeFlowControl))
		}
	}
	return nil
}

func (sc *http2serverConn) processData(f *http2DataFrame) error {
	sc.serveG.check()
	id := f.Header().StreamID

	data := f.Data()
	state, st := sc.state(id)
	if id == 0 || state == http2stateIdle {
		// Section 6.1: "DATA frames MUST be associated with a
		// stream. If a DATA frame is received whose stream
		// identifier field is 0x0, the recipient MUST respond
		// with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR."
		//
		// Section 5.1: "Receiving any frame other than HEADERS
		// or PRIORITY on a stream in this state MUST be
		// treated as a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR."
		return sc.countError("data_on_idle", http2ConnectionError(http2ErrCodeProtocol))
	}

	// "If a DATA frame is received whose stream is not in "open"
	// or "half closed (local)" state, the recipient MUST respond
	// with a stream error (Section 5.4.2) of type STREAM_CLOSED."
	if st == nil || state != http2stateOpen || st.gotTrailerHeader || st.resetQueued {
		// This includes sending a RST_STREAM if the stream is
		// in stateHalfClosedLocal (which currently means that
		// the http.Handler returned, so it's done reading &
		// done writing). Try to stop the client from sending
		// more DATA.

		// But still enforce their connection-level flow control,
		// and return any flow control bytes since we're not going
		// to consume them.
		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", http2streamError(id, http2ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length)) // conn-level

		if st != nil && st.resetQueued {
			// Already have a stream error in flight. Don't send another.
			return nil
		}
		return sc.countError("closed", http2streamError(id, http2ErrCodeStreamClosed))
	}
	if st.body == nil {
		panic("internal error: should have a body in this state")
	}

	// Sender sending more than they'd declared?
	if st.declBodyBytes != -1 && st.bodyBytes+int64(len(data)) > st.declBodyBytes {
		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", http2streamError(id, http2ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length)) // conn-level

		st.body.CloseWithError(fmt.Errorf("sender tried to send more than declared Content-Length of %d bytes", st.declBodyBytes))
		// RFC 7540, sec 8.1.2.6: A request or response is also malformed if the
		// value of a content-length header field does not equal the sum of the
		// DATA frame payload lengths that form the body.
		return sc.countError("send_too_much", http2streamError(id, http2ErrCodeProtocol))
	}
	if f.Length > 0 {
		// Check whether the client has flow control quota.
		if !http2takeInflows(&sc.inflow, &st.inflow, f.Length) {
			return sc.countError("flow_on_data_length", http2streamError(id, http2ErrCodeFlowControl))
		}

		if len(data) > 0 {
			st.bodyBytes += int64(len(data))
			wrote, err := st.body.Write(data)
			if err != nil {
				// The handler has closed the request body.
				// Return the connection-level flow control for the discarded data,
				// but not the stream-level flow control.
				sc.sendWindowUpdate(nil, int(f.Length)-wrote)
				return nil
			}
			if wrote != len(data) {
				panic("internal error: bad Writer")
			}
		}

		// Return any padded flow control now, since we won't
		// refund it later on body reads.
		// Call sendWindowUpdate even if there is no padding,
		// to return buffered flow control credit if the sent
		// window has shrunk.
		pad := int32(f.Length) - int32(len(data))
		sc.sendWindowUpdate32(nil, pad)
		sc.sendWindowUpdate32(st, pad)
	}
	if f.StreamEnded() {
		st.endStream()
	}
	return nil
}

func (sc *http2serverConn) processGoAway(f *http2GoAwayFrame) error {
	sc.serveG.check()
	if f.ErrCode != http2ErrCodeNo {
		sc.logf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	} else {
		sc.vlogf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	}
	sc.startGracefulShutdownInternal()
	// http://tools.ietf.org/html/rfc7540#section-6.8
	// We should not create any new streams, which means we should disable push.
	sc.pushEnabled = false
	return nil
}

// isPushed reports whether the stream is server-initiated.
func (st *http2stream) isPushed() bool {
	return st.id%2 == 0
}

// endStream closes a Request.Body's pipe. It is called when a DATA
// frame says a request body is over (or after trailers).
func (st *http2stream) endStream() {
	sc := st.sc
	sc.serveG.check()

	if st.declBodyBytes != -1 && st.declBodyBytes != st.bodyBytes {
		st.body.CloseWithError(fmt.Errorf("request declared a Content-Length of %d but only wrote %d bytes",
			st.declBodyBytes, st.bodyBytes))
	} else {
		st.body.closeWithErrorAndCode(io.EOF, st.copyTrailersToHandlerRequest)
		st.body.CloseWithError(io.EOF)
	}
	st.state = http2stateHalfClosedRemote
}

// copyTrailersToHandlerRequest is run in the Handler's goroutine in
// its Request.Body.Read just before it gets io.EOF.
func (st *http2stream) copyTrailersToHandlerRequest() {
	for k, vv := range st.trailer {
		if _, ok := st.reqTrailer[k]; ok {
			// Only copy it over it was pre-declared.
			st.reqTrailer[k] = vv
		}
	}
}

// onReadTimeout is run on its own goroutine (from time.AfterFunc)
// when the stream's ReadTimeout has fired.
func (st *http2stream) onReadTimeout() {
	// Wrap the ErrDeadlineExceeded to avoid callers depending on us
	// returning the bare error.
	st.body.CloseWithError(fmt.Errorf("%w", os.ErrDeadlineExceeded))
}

// onWriteTimeout is run on its own goroutine (from time.AfterFunc)
// when the stream's WriteTimeout has fired.
func (st *http2stream) onWriteTimeout() {
	st.sc.writeFrameFromHandler(http2FrameWriteRequest{write: http2StreamError{
		StreamID: st.id,
		Code:     http2ErrCodeInternal,
		Cause:    os.ErrDeadlineExceeded,
	}})
}

func (sc *http2serverConn) processHeaders(f *http2MetaHeadersFrame) error {
	sc.serveG.check()
	id := f.StreamID
	// http://tools.ietf.org/html/rfc7540#section-5.1.1
	// Streams initiated by a client MUST use odd-numbered stream
	// identifiers. [...] An endpoint that receives an unexpected
	// stream identifier MUST respond with a connection error
	// (Section 5.4.1) of type PROTOCOL_ERROR.
	if id%2 != 1 {
		return sc.countError("headers_even", http2ConnectionError(http2ErrCodeProtocol))
	}
	// A HEADERS frame can be used to create a new stream or
	// send a trailer for an open one. If we already have a stream
	// open, let it process its own HEADERS frame (trailers at this
	// point, if it's valid).
	if st := sc.streams[f.StreamID]; st != nil {
		if st.resetQueued {
			// We're sending RST_STREAM to close the stream, so don't bother
			// processing this frame.
			return nil
		}
		// RFC 7540, sec 5.1: If an endpoint receives additional frames, other than
		// WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in
		// this state, it MUST respond with a stream error (Section 5.4.2) of
		// type STREAM_CLOSED.
		if st.state == http2stateHalfClosedRemote {
			return sc.countError("headers_half_closed", http2streamError(id, http2ErrCodeStreamClosed))
		}
		return st.processTrailerHeaders(f)
	}

	// [...] The identifier of a newly established stream MUST be
	// numerically greater than all streams that the initiating
	// endpoint has opened or reserved. [...]  An endpoint that
	// receives an unexpected stream identifier MUST respond with
	// a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
	if id <= sc.maxClientStreamID {
		return sc.countError("stream_went_down", http2ConnectionError(http2ErrCodeProtocol))
	}
	sc.maxClientStreamID = id

	if sc.idleTimer != nil {
		sc.idleTimer.Stop()
	}

	// http://tools.ietf.org/html/rfc7540#section-5.1.2
	// [...] Endpoints MUST NOT exceed the limit set by their peer. An
	// endpoint that receives a HEADERS frame that causes their
	// advertised concurrent stream limit to be exceeded MUST treat
	// this as a stream error (Section 5.4.2) of type PROTOCOL_ERROR
	// or REFUSED_STREAM.
	if sc.curClientStreams+1 > sc.advMaxStreams {
		if sc.unackedSettings == 0 {
			// They should know better.
			return sc.countError("over_max_streams", http2streamError(id, http2ErrCodeProtocol))
		}
		// Assume it's a network race, where they just haven't
		// received our last SETTINGS update. But actually
		// this can't happen yet, because we don't yet provide
		// a way for users to adjust server parameters at
		// runtime.
		return sc.countError("over_max_streams_race", http2streamError(id, http2ErrCodeRefusedStream))
	}

	initialState := http2stateOpen
	if f.StreamEnded() {
		initialState = http2stateHalfClosedRemote
	}
	st := sc.newStream(id, 0, initialState)

	if f.HasPriority() {
		if err := sc.checkPriority(f.StreamID, f.Priority); err != nil {
			return err
		}
		sc.writeSched.AdjustStream(st.id, f.Priority)
	}

	rw, req, err := sc.newWriterAndRequest(st, f)
	if err != nil {
		return err
	}
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(http.Header)
	}
	st.body = req.Body.(*http2requestBody).pipe // may be nil
	st.declBodyBytes = req.ContentLength

	handler := sc.handler.ServeHTTP
	if f.Truncated {
		// Their header list was too long. Send a 431 error.
		handler = http2handleHeaderListTooLong
	} else if err := http2checkValidHTTP2RequestHeaders(req.Header); err != nil {
		handler = http2new400Handler(err)
	}

	// The net/http package sets the read deadline from the
	// http.Server.ReadTimeout during the TLS handshake, but then
	// passes the connection off to us with the deadline already
	// set. Disarm it here after the request headers are read,
	// similar to how the http1 server works. Here it's
	// technically more like the http1 Server's ReadHeaderTimeout
	// (in Go 1.8), though. That's a more sane option anyway.
	if sc.hs.ReadTimeout != 0 {
		sc.conn.SetReadDeadline(time.Time{})
		if st.body != nil {
			st.readDeadline = time.AfterFunc(sc.hs.ReadTimeout, st.onReadTimeout)
		}
	}

	return sc.scheduleHandler(id, rw, req, handler)
}

func (sc *http2serverConn) upgradeRequest(req *http.Request) {
	sc.serveG.check()
	id := uint32(1)
	sc.maxClientStreamID = id
	st := sc.newStream(id, 0, http2stateHalfClosedRemote)
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(http.Header)
	}
	rw := sc.newResponseWriter(st, req)

	// Disable any read deadline set by the net/http package
	// prior to the upgrade.
	if sc.hs.ReadTimeout != 0 {
		sc.conn.SetReadDeadline(time.Time{})
	}

	// This is the first request on the connection,
	// so start the handler directly rather than going
	// through scheduleHandler.
	sc.curHandlers++
	go sc.runHandler(rw, req, sc.handler.ServeHTTP)
}

func (st *http2stream) processTrailerHeaders(f *http2MetaHeadersFrame) error {
	sc := st.sc
	sc.serveG.check()
	if st.gotTrailerHeader {
		return sc.countError("dup_trailers", http2ConnectionError(http2ErrCodeProtocol))
	}
	st.gotTrailerHeader = true
	if !f.StreamEnded() {
		return sc.countError("trailers_not_ended", http2streamError(st.id, http2ErrCodeProtocol))
	}

	if len(f.PseudoFields()) > 0 {
		return sc.countError("trailers_pseudo", http2streamError(st.id, http2ErrCodeProtocol))
	}
	if st.trailer != nil {
		for _, hf := range f.RegularFields() {
			key := sc.canonicalHeader(hf.Name)
			if !httpguts.ValidTrailerHeader(key) {
				// TODO: send more details to the peer somehow. But http2 has
				// no way to send debug data at a stream level. Discuss with
				// HTTP folk.
				return sc.countError("trailers_bogus", http2streamError(st.id, http2ErrCodeProtocol))
			}
			st.trailer[key] = append(st.trailer[key], hf.Value)
		}
	}
	st.endStream()
	return nil
}

func (sc *http2serverConn) checkPriority(streamID uint32, p http2PriorityParam) error {
	if streamID == p.StreamDep {
		// Section 5.3.1: "A stream cannot depend on itself. An endpoint MUST treat
		// this as a stream error (Section 5.4.2) of type PROTOCOL_ERROR."
		// Section 5.3.3 says that a stream can depend on one of its dependencies,
		// so it's only self-dependencies that are forbidden.
		return sc.countError("priority", http2streamError(streamID, http2ErrCodeProtocol))
	}
	return nil
}

func (sc *http2serverConn) processPriority(f *http2PriorityFrame) error {
	if err := sc.checkPriority(f.StreamID, f.http2PriorityParam); err != nil {
		return err
	}
	sc.writeSched.AdjustStream(f.StreamID, f.http2PriorityParam)
	return nil
}

func (sc *http2serverConn) newStream(id, pusherID uint32, state http2streamState) *http2stream {
	sc.serveG.check()
	if id == 0 {
		panic("internal error: cannot create stream with id 0")
	}

	ctx, cancelCtx := context.WithCancel(sc.baseCtx)
	st := &http2stream{
		sc:        sc,
		id:        id,
		state:     state,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}
	st.cw.Init()
	st.flow.conn = &sc.flow // link to conn-level counter
	st.flow.add(sc.initialStreamSendWindowSize)
	st.inflow.init(sc.srv.initialStreamRecvWindowSize())
	if sc.hs.WriteTimeout != 0 {
		st.writeDeadline = time.AfterFunc(sc.hs.WriteTimeout, st.onWriteTimeout)
	}

	sc.streams[id] = st
	sc.writeSched.OpenStream(st.id, http2OpenStreamOptions{PusherID: pusherID})
	if st.isPushed() {
		sc.curPushedStreams++
	} else {
		sc.curClientStreams++
	}
	if sc.curOpenStreams() == 1 {
		sc.setConnState(http.StateActive)
	}

	return st
}

func (sc *http2serverConn) newWriterAndRequest(st *http2stream, f *http2MetaHeadersFrame) (*http2responseWriter, *http.Request, error) {
	sc.serveG.check()

	rp := http2requestParam{
		method:    f.PseudoValue("method"),
		scheme:    f.PseudoValue("scheme"),
		authority: f.PseudoValue("authority"),
		path:      f.PseudoValue("path"),
	}

	isConnect := rp.method == "CONNECT"
	if isConnect {
		if rp.path != "" || rp.scheme != "" || rp.authority == "" {
			return nil, nil, sc.countError("bad_connect", http2streamError(f.StreamID, http2ErrCodeProtocol))
		}
	} else if rp.method == "" || rp.path == "" || (rp.scheme != "https" && rp.scheme != "http") {
		// See 8.1.2.6 Malformed Requests and Responses:
		//
		// Malformed requests or responses that are detected
		// MUST be treated as a stream error (Section 5.4.2)
		// of type PROTOCOL_ERROR."
		//
		// 8.1.2.3 Request Pseudo-Header Fields
		// "All HTTP/2 requests MUST include exactly one valid
		// value for the :method, :scheme, and :path
		// pseudo-header fields"
		return nil, nil, sc.countError("bad_path_method", http2streamError(f.StreamID, http2ErrCodeProtocol))
	}

	rp.header = make(http.Header)
	for _, hf := range f.RegularFields() {
		rp.header.Add(sc.canonicalHeader(hf.Name), hf.Value)
	}
	if rp.authority == "" {
		rp.authority = rp.header.Get("Host")
	}

	rw, req, err := sc.newWriterAndRequestNoBody(st, rp)
	if err != nil {
		return nil, nil, err
	}
	bodyOpen := !f.StreamEnded()
	if bodyOpen {
		if vv, ok := rp.header["Content-Length"]; ok {
			if cl, err := strconv.ParseUint(vv[0], 10, 63); err == nil {
				req.ContentLength = int64(cl)
			} else {
				req.ContentLength = 0
			}
		} else {
			req.ContentLength = -1
		}
		req.Body.(*http2requestBody).pipe = &http2pipe{
			b: &http2dataBuffer{expected: req.ContentLength},
		}
	}
	return rw, req, nil
}

type http2requestParam struct {
	method                  string
	scheme, authority, path string
	header                  http.Header
}

func (sc *http2serverConn) newWriterAndRequestNoBody(st *http2stream, rp http2requestParam) (*http2responseWriter, *http.Request, error) {
	sc.serveG.check()

	var tlsState *tls.ConnectionState // nil if not scheme https
	if rp.scheme == "https" {
		tlsState = sc.tlsState
	}

	needsContinue := httpguts.HeaderValuesContainsToken(rp.header["Expect"], "100-continue")
	if needsContinue {
		rp.header.Del("Expect")
	}
	// Merge Cookie headers into one "; "-delimited value.
	if cookies := rp.header["Cookie"]; len(cookies) > 1 {
		rp.header.Set("Cookie", strings.Join(cookies, "; "))
	}

	// Setup Trailers
	var trailer http.Header
	for _, v := range rp.header["Trailer"] {
		for _, key := range strings.Split(v, ",") {
			key = http.CanonicalHeaderKey(textproto.TrimString(key))
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				// Bogus. (copy of http1 rules)
				// Ignore.
			default:
				if trailer == nil {
					trailer = make(http.Header)
				}
				trailer[key] = nil
			}
		}
	}
	delete(rp.header, "Trailer")

	var url_ *url.URL
	var requestURI string
	if rp.method == "CONNECT" {
		url_ = &url.URL{Host: rp.authority}
		requestURI = rp.authority // mimic HTTP/1 server behavior
	} else {
		var err error
		url_, err = url.ParseRequestURI(rp.path)
		if err != nil {
			return nil, nil, sc.countError("bad_path", http2streamError(st.id, http2ErrCodeProtocol))
		}
		requestURI = rp.path
	}

	body := &http2requestBody{
		conn:          sc,
		stream:        st,
		needsContinue: needsContinue,
	}
	req := &http.Request{
		Method:     rp.method,
		URL:        url_,
		RemoteAddr: sc.remoteAddrStr,
		Header:     rp.header,
		RequestURI: requestURI,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		TLS:        tlsState,
		Host:       rp.authority,
		Body:       body,
		Trailer:    trailer,
	}
	req = req.WithContext(st.ctx)

	rw := sc.newResponseWriter(st, req)
	return rw, req, nil
}

func (sc *http2serverConn) newResponseWriter(st *http2stream, req *http.Request) *http2responseWriter {
	rws := http2responseWriterStatePool.Get().(*http2responseWriterState)
	bwSave := rws.bw
	*rws = http2responseWriterState{} // zero all the fields
	rws.conn = sc
	rws.bw = bwSave
	rws.bw.Reset(http2chunkWriter{rws})
	rws.stream = st
	rws.req = req
	return &http2responseWriter{rws: rws}
}

type http2unstartedHandler struct {
	streamID uint32
	rw       *http2responseWriter
	req      *http.Request
	handler  func(http.ResponseWriter, *http.Request)
}

// scheduleHandler starts a handler goroutine,
// or schedules one to start as soon as an existing handler finishes.
func (sc *http2serverConn) scheduleHandler(streamID uint32, rw *http2responseWriter, req *http.Request, handler func(http.ResponseWriter, *http.Request)) error {
	sc.serveG.check()
	maxHandlers := sc.advMaxStreams
	if sc.curHandlers < maxHandlers {
		sc.curHandlers++
		go sc.runHandler(rw, req, handler)
		return nil
	}
	if len(sc.unstartedHandlers) > int(4*sc.advMaxStreams) {
		return sc.countError("too_many_early_resets", http2ConnectionError(http2ErrCodeEnhanceYourCalm))
	}
	sc.unstartedHandlers = append(sc.unstartedHandlers, http2unstartedHandler{
		streamID: streamID,
		rw:       rw,
		req:      req,
		handler:  handler,
	})
	return nil
}

func (sc *http2serverConn) handlerDone() {
	sc.serveG.check()
	sc.curHandlers--
	i := 0
	maxHandlers := sc.advMaxStreams
	for ; i < len(sc.unstartedHandlers); i++ {
		u := sc.unstartedHandlers[i]
		if sc.streams[u.streamID] == nil {
			// This stream was reset before its goroutine had a chance to start.
			continue
		}
		if sc.curHandlers >= maxHandlers {
			break
		}
		sc.curHandlers++
		go sc.runHandler(u.rw, u.req, u.handler)
		sc.unstartedHandlers[i] = http2unstartedHandler{} // don't retain references
	}
	sc.unstartedHandlers = sc.unstartedHandlers[i:]
	if len(sc.unstartedHandlers) == 0 {
		sc.unstartedHandlers = nil
	}
}

// Run on its own goroutine.
func (sc *http2serverConn) runHandler(rw *http2responseWriter, req *http.Request, handler func(http.ResponseWriter, *http.Request)) {
	defer sc.sendServeMsg(http2handlerDoneMsg)
	didPanic := true
	defer func() {
		rw.rws.stream.cancelCtx()
		if req.MultipartForm != nil {
			req.MultipartForm.RemoveAll()
		}
		if didPanic {
			e := recover()
			sc.writeFrameFromHandler(http2FrameWriteRequest{
				write:  http2handlerPanicRST{rw.rws.stream.id},
				stream: rw.rws.stream,
			})
			// Same as net/http:
			if e != nil && e != ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				sc.logf("http2: panic serving %v: %v\n%s", sc.conn.RemoteAddr(), e, buf)
			}
			return
		}
		rw.handlerDone()
	}()
	handler(rw, req)
	didPanic = false
}

func http2handleHeaderListTooLong(w http.ResponseWriter, r *http.Request) {
	// 10.5.1 Limits on Header Block Size:
	// .. "A server that receives a larger header block than it is
	// willing to handle can send an HTTP 431 (Request Header Fields Too
	// Large) status code"
	const statusRequestHeaderFieldsTooLarge = 431 // only in Go 1.6+
	w.WriteHeader(statusRequestHeaderFieldsTooLarge)
	io.WriteString(w, "<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>")
}

// called from handler goroutines.
// h may be nil.
func (sc *http2serverConn) writeHeaders(st *http2stream, headerData *http2writeResHeaders) error {
	sc.serveG.checkNotOn() // NOT on
	var errc chan error
	if headerData.h != nil {
		// If there's a header map (which we don't own), so we have to block on
		// waiting for this frame to be written, so an http.Flush mid-handler
		// writes out the correct value of keys, before a handler later potentially
		// mutates it.
		errc = http2errChanPool.Get().(chan error)
	}
	if err := sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  headerData,
		stream: st,
		done:   errc,
	}); err != nil {
		return err
	}
	if errc != nil {
		select {
		case err := <-errc:
			http2errChanPool.Put(errc)
			return err
		case <-sc.doneServing:
			return http2errClientDisconnected
		case <-st.cw:
			return http2errStreamClosed
		}
	}
	return nil
}

// called from handler goroutines.
func (sc *http2serverConn) write100ContinueHeaders(st *http2stream) {
	sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  http2write100ContinueHeadersFrame{st.id},
		stream: st,
	})
}

// A bodyReadMsg tells the server loop that the http.Handler read n
// bytes of the DATA from the client on the given stream.
type http2bodyReadMsg struct {
	st *http2stream
	n  int
}

// called from handler goroutines.
// Notes that the handler for the given stream ID read n bytes of its body
// and schedules flow control tokens to be sent.
func (sc *http2serverConn) noteBodyReadFromHandler(st *http2stream, n int, err error) {
	sc.serveG.checkNotOn() // NOT on
	if n > 0 {
		select {
		case sc.bodyReadCh <- http2bodyReadMsg{st, n}:
		case <-sc.doneServing:
		}
	}
}

func (sc *http2serverConn) noteBodyRead(st *http2stream, n int) {
	sc.serveG.check()
	sc.sendWindowUpdate(nil, n) // conn-level
	if st.state != http2stateHalfClosedRemote && st.state != http2stateClosed {
		// Don't send this WINDOW_UPDATE if the stream is closed
		// remotely.
		sc.sendWindowUpdate(st, n)
	}
}

// st may be nil for conn-level
func (sc *http2serverConn) sendWindowUpdate32(st *http2stream, n int32) {
	sc.sendWindowUpdate(st, int(n))
}

// st may be nil for conn-level
func (sc *http2serverConn) sendWindowUpdate(st *http2stream, n int) {
	sc.serveG.check()
	var streamID uint32
	var send int32
	if st == nil {
		send = sc.inflow.add(n)
	} else {
		streamID = st.id
		send = st.inflow.add(n)
	}
	if send == 0 {
		return
	}
	sc.writeFrame(http2FrameWriteRequest{
		write:  http2writeWindowUpdate{streamID: streamID, n: uint32(send)},
		stream: st,
	})
}

// requestBody is the Handler's Request.Body type.
// Read and Close may be called concurrently.
type http2requestBody struct {
	_             http2incomparable
	stream        *http2stream
	conn          *http2serverConn
	closeOnce     sync.Once  // for use by Close only
	sawEOF        bool       // for use by Read only
	pipe          *http2pipe // non-nil if we have an HTTP entity message body
	needsContinue bool       // need to send a 100-continue
}

func (b *http2requestBody) Close() error {
	b.closeOnce.Do(func() {
		if b.pipe != nil {
			b.pipe.BreakWithError(http2errClosedBody)
		}
	})
	return nil
}

func (b *http2requestBody) Read(p []byte) (n int, err error) {
	if b.needsContinue {
		b.needsContinue = false
		b.conn.write100ContinueHeaders(b.stream)
	}
	if b.pipe == nil || b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.pipe.Read(p)
	if err == io.EOF {
		b.sawEOF = true
	}
	if b.conn == nil && http2inTests {
		return
	}
	b.conn.noteBodyReadFromHandler(b.stream, n, err)
	return
}

// responseWriter is the http.ResponseWriter implementation. It's
// intentionally small (1 pointer wide) to minimize garbage. The
// responseWriterState pointer inside is zeroed at the end of a
// request (in handlerDone) and calls on the responseWriter thereafter
// simply crash (caller's mistake), but the much larger responseWriterState
// and buffers are reused between multiple requests.
type http2responseWriter struct {
	rws *http2responseWriterState
}

// Optional http.ResponseWriter interfaces implemented.
var (
	_ http.CloseNotifier = (*http2responseWriter)(nil)
	_ http.Flusher       = (*http2responseWriter)(nil)
	_ http2stringWriter  = (*http2responseWriter)(nil)
)

type http2responseWriterState struct {
	// immutable within a request:
	stream *http2stream
	req    *http.Request
	conn   *http2serverConn

	// TODO: adjust buffer writing sizes based on server config, frame size updates from peer, etc
	bw *bufio.Writer // writing to a chunkWriter{this *responseWriterState}

	// mutated by http.Handler goroutine:
	handlerHeader http.Header // nil until called
	snapHeader    http.Header // snapshot of handlerHeader at WriteHeader time
	trailers      []string    // set in writeChunk
	status        int         // status code passed to WriteHeader
	wroteHeader   bool        // WriteHeader called (explicitly or implicitly). Not necessarily sent to user yet.
	sentHeader    bool        // have we sent the header frame?
	handlerDone   bool        // handler has finished
	dirty         bool        // a Write failed; don't reuse this responseWriterState

	sentContentLen int64 // non-zero if handler set a Content-Length header
	wroteBytes     int64

	closeNotifierMu sync.Mutex // guards closeNotifierCh
	closeNotifierCh chan bool  // nil until first used
}

type http2chunkWriter struct{ rws *http2responseWriterState }

func (cw http2chunkWriter) Write(p []byte) (n int, err error) {
	n, err = cw.rws.writeChunk(p)
	if err == http2errStreamClosed {
		// If writing failed because the stream has been closed,
		// return the reason it was closed.
		err = cw.rws.stream.closeErr
	}
	return n, err
}

func (rws *http2responseWriterState) hasTrailers() bool { return len(rws.trailers) > 0 }

func (rws *http2responseWriterState) hasNonemptyTrailers() bool {
	for _, trailer := range rws.trailers {
		if _, ok := rws.handlerHeader[trailer]; ok {
			return true
		}
	}
	return false
}

// declareTrailer is called for each Trailer header when the
// response header is written. It notes that a header will need to be
// written in the trailers at the end of the response.
func (rws *http2responseWriterState) declareTrailer(k string) {
	k = http.CanonicalHeaderKey(k)
	if !httpguts.ValidTrailerHeader(k) {
		// Forbidden by RFC 7230, section 4.1.2.
		rws.conn.logf("ignoring invalid trailer %q", k)
		return
	}
	if !http2strSliceContains(rws.trailers, k) {
		rws.trailers = append(rws.trailers, k)
	}
}

// writeChunk writes chunks from the bufio.Writer. But because
// bufio.Writer may bypass its chunking, sometimes p may be
// arbitrarily large.
//
// writeChunk is also responsible (on the first chunk) for sending the
// HEADER response.
func (rws *http2responseWriterState) writeChunk(p []byte) (n int, err error) {
	if !rws.wroteHeader {
		rws.writeHeader(200)
	}

	if rws.handlerDone {
		rws.promoteUndeclaredTrailers()
	}

	isHeadResp := rws.req.Method == "HEAD"
	if !rws.sentHeader {
		rws.sentHeader = true
		var ctype, clen string
		if clen = rws.snapHeader.Get("Content-Length"); clen != "" {
			rws.snapHeader.Del("Content-Length")
			if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
				rws.sentContentLen = int64(cl)
			} else {
				clen = ""
			}
		}
		_, hasContentLength := rws.snapHeader["Content-Length"]
		if !hasContentLength && clen == "" && rws.handlerDone && http2bodyAllowedForStatus(rws.status) && (len(p) > 0 || !isHeadResp) {
			clen = strconv.Itoa(len(p))
		}
		_, hasContentType := rws.snapHeader["Content-Type"]
		// If the Content-Encoding is non-blank, we shouldn't
		// sniff the body. See Issue golang.org/issue/31753.
		ce := rws.snapHeader.Get("Content-Encoding")
		hasCE := len(ce) > 0
		if !hasCE && !hasContentType && http2bodyAllowedForStatus(rws.status) && len(p) > 0 {
			ctype = http.DetectContentType(p)
		}
		var date string
		if _, ok := rws.snapHeader["Date"]; !ok {
			// TODO(bradfitz): be faster here, like net/http? measure.
			date = time.Now().UTC().Format(TimeFormat)
		}

		for _, v := range rws.snapHeader["Trailer"] {
			http2foreachHeaderElement(v, rws.declareTrailer)
		}

		// "Connection" headers aren't allowed in HTTP/2 (RFC 7540, 8.1.2.2),
		// but respect "Connection" == "close" to mean sending a GOAWAY and tearing
		// down the TCP connection when idle, like we do for HTTP/1.
		// TODO: remove more Connection-specific header fields here, in addition
		// to "Connection".
		if _, ok := rws.snapHeader["Connection"]; ok {
			v := rws.snapHeader.Get("Connection")
			delete(rws.snapHeader, "Connection")
			if v == "close" {
				rws.conn.startGracefulShutdown()
			}
		}

		endStream := (rws.handlerDone && !rws.hasTrailers() && len(p) == 0) || isHeadResp
		err = rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:      rws.stream.id,
			httpResCode:   rws.status,
			h:             rws.snapHeader,
			endStream:     endStream,
			contentType:   ctype,
			contentLength: clen,
			date:          date,
		})
		if err != nil {
			rws.dirty = true
			return 0, err
		}
		if endStream {
			return 0, nil
		}
	}
	if isHeadResp {
		return len(p), nil
	}
	if len(p) == 0 && !rws.handlerDone {
		return 0, nil
	}

	// only send trailers if they have actually been defined by the
	// server handler.
	hasNonemptyTrailers := rws.hasNonemptyTrailers()
	endStream := rws.handlerDone && !hasNonemptyTrailers
	if len(p) > 0 || endStream {
		// only send a 0 byte DATA frame if we're ending the stream.
		if err := rws.conn.writeDataFromHandler(rws.stream, p, endStream); err != nil {
			rws.dirty = true
			return 0, err
		}
	}

	if rws.handlerDone && hasNonemptyTrailers {
		err = rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:  rws.stream.id,
			h:         rws.handlerHeader,
			trailers:  rws.trailers,
			endStream: true,
		})
		if err != nil {
			rws.dirty = true
		}
		return len(p), err
	}
	return len(p), nil
}

// TrailerPrefix is a magic prefix for ResponseWriter.Header map keys
// that, if present, signals that the map entry is actually for
// the response trailers, and not the response headers. The prefix
// is stripped after the ServeHTTP call finishes and the values are
// sent in the trailers.
//
// This mechanism is intended only for trailers that are not known
// prior to the headers being written. If the set of trailers is fixed
// or known before the header is written, the normal Go trailers mechanism
// is preferred:
//
//	https://golang.org/pkg/net/http/#ResponseWriter
//	https://golang.org/pkg/net/http/#example_ResponseWriter_trailers
const http2TrailerPrefix = "Trailer:"

// promoteUndeclaredTrailers permits http.Handlers to set trailers
// after the header has already been flushed. Because the Go
// ResponseWriter interface has no way to set Trailers (only the
// Header), and because we didn't want to expand the ResponseWriter
// interface, and because nobody used trailers, and because RFC 7230
// says you SHOULD (but not must) predeclare any trailers in the
// header, the official ResponseWriter rules said trailers in Go must
// be predeclared, and then we reuse the same ResponseWriter.Header()
// map to mean both Headers and Trailers. When it's time to write the
// Trailers, we pick out the fields of Headers that were declared as
// trailers. That worked for a while, until we found the first major
// user of Trailers in the wild: gRPC (using them only over http2),
// and gRPC libraries permit setting trailers mid-stream without
// predeclaring them. So: change of plans. We still permit the old
// way, but we also permit this hack: if a Header() key begins with
// "Trailer:", the suffix of that key is a Trailer. Because ':' is an
// invalid token byte anyway, there is no ambiguity. (And it's already
// filtered out) It's mildly hacky, but not terrible.
//
// This method runs after the Handler is done and promotes any Header
// fields to be trailers.
func (rws *http2responseWriterState) promoteUndeclaredTrailers() {
	for k, vv := range rws.handlerHeader {
		if !strings.HasPrefix(k, http2TrailerPrefix) {
			continue
		}
		trailerKey := strings.TrimPrefix(k, http2TrailerPrefix)
		rws.declareTrailer(trailerKey)
		rws.handlerHeader[http.CanonicalHeaderKey(trailerKey)] = vv
	}

	if len(rws.trailers) > 1 {
		sorter := http2sorterPool.Get().(*http2sorter)
		sorter.SortStrings(rws.trailers)
		http2sorterPool.Put(sorter)
	}
}

func (w *http2responseWriter) SetReadDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(time.Now()) {
		// If we're setting a deadline in the past, reset the stream immediately
		// so writes after SetWriteDeadline returns will fail.
		st.onReadTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *http2serverConn) {
		if st.readDeadline != nil {
			if !st.readDeadline.Stop() {
				// Deadline already exceeded, or stream has been closed.
				return
			}
		}
		if deadline.IsZero() {
			st.readDeadline = nil
		} else if st.readDeadline == nil {
			st.readDeadline = time.AfterFunc(deadline.Sub(time.Now()), st.onReadTimeout)
		} else {
			st.readDeadline.Reset(deadline.Sub(time.Now()))
		}
	})
	return nil
}

func (w *http2responseWriter) SetWriteDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(time.Now()) {
		// If we're setting a deadline in the past, reset the stream immediately
		// so writes after SetWriteDeadline returns will fail.
		st.onWriteTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *http2serverConn) {
		if st.writeDeadline != nil {
			if !st.writeDeadline.Stop() {
				// Deadline already exceeded, or stream has been closed.
				return
			}
		}
		if deadline.IsZero() {
			st.writeDeadline = nil
		} else if st.writeDeadline == nil {
			st.writeDeadline = time.AfterFunc(deadline.Sub(time.Now()), st.onWriteTimeout)
		} else {
			st.writeDeadline.Reset(deadline.Sub(time.Now()))
		}
	})
	return nil
}

func (w *http2responseWriter) Flush() {
	w.FlushError()
}

func (w *http2responseWriter) FlushError() error {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	var err error
	if rws.bw.Buffered() > 0 {
		err = rws.bw.Flush()
	} else {
		// The bufio.Writer won't call chunkWriter.Write
		// (writeChunk with zero bytes), so we have to do it
		// ourselves to force the HTTP response header and/or
		// final DATA frame (with END_STREAM) to be sent.
		_, err = http2chunkWriter{rws}.Write(nil)
		if err == nil {
			select {
			case <-rws.stream.cw:
				err = rws.stream.closeErr
			default:
			}
		}
	}
	return err
}

func (w *http2responseWriter) CloseNotify() <-chan bool {
	rws := w.rws
	if rws == nil {
		panic("CloseNotify called after Handler finished")
	}
	rws.closeNotifierMu.Lock()
	ch := rws.closeNotifierCh
	if ch == nil {
		ch = make(chan bool, 1)
		rws.closeNotifierCh = ch
		cw := rws.stream.cw
		go func() {
			cw.Wait() // wait for close
			ch <- true
		}()
	}
	rws.closeNotifierMu.Unlock()
	return ch
}

func (w *http2responseWriter) Header() http.Header {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	if rws.handlerHeader == nil {
		rws.handlerHeader = make(http.Header)
	}
	return rws.handlerHeader
}

// checkWriteHeaderCode is a copy of net/http's checkWriteHeaderCode.
func http2checkWriteHeaderCode(code int) {
	// Issue 22880: require valid WriteHeader status codes.
	// For now we only enforce that it's three digits.
	// In the future we might block things over 599 (600 and above aren't defined
	// at http://httpwg.org/specs/rfc7231.html#status.codes).
	// But for now any three digits.
	//
	// We used to send "HTTP/1.1 000 0" on the wire in responses but there's
	// no equivalent bogus thing we can realistically send in HTTP/2,
	// so we'll consistently panic instead and help people find their bugs
	// early. (We can't return an error from WriteHeader even if we wanted to.)
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
}

func (w *http2responseWriter) WriteHeader(code int) {
	rws := w.rws
	if rws == nil {
		panic("WriteHeader called after Handler finished")
	}
	rws.writeHeader(code)
}

func (rws *http2responseWriterState) writeHeader(code int) {
	if rws.wroteHeader {
		return
	}

	http2checkWriteHeaderCode(code)

	// Handle informational headers
	if code >= 100 && code <= 199 {
		// Per RFC 8297 we must not clear the current header map
		h := rws.handlerHeader

		_, cl := h["Content-Length"]
		_, te := h["Transfer-Encoding"]
		if cl || te {
			h = h.Clone()
			h.Del("Content-Length")
			h.Del("Transfer-Encoding")
		}

		if rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:    rws.stream.id,
			httpResCode: code,
			h:           h,
			endStream:   rws.handlerDone && !rws.hasTrailers(),
		}) != nil {
			rws.dirty = true
		}

		return
	}

	rws.wroteHeader = true
	rws.status = code
	if len(rws.handlerHeader) > 0 {
		rws.snapHeader = http2cloneHeader(rws.handlerHeader)
	}
}

func http2cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// The Life Of A Write is like this:
//
// * Handler calls w.Write or w.WriteString ->
// * -> rws.bw (*bufio.Writer) ->
// * (Handler might call Flush)
// * -> chunkWriter{rws}
// * -> responseWriterState.writeChunk(p []byte)
// * -> responseWriterState.writeChunk (most of the magic; see comment there)
func (w *http2responseWriter) Write(p []byte) (n int, err error) {
	return w.write(len(p), p, "")
}

func (w *http2responseWriter) WriteString(s string) (n int, err error) {
	return w.write(len(s), nil, s)
}

// either dataB or dataS is non-zero.
func (w *http2responseWriter) write(lenData int, dataB []byte, dataS string) (n int, err error) {
	rws := w.rws
	if rws == nil {
		panic("Write called after Handler finished")
	}
	if !rws.wroteHeader {
		w.WriteHeader(200)
	}
	if !http2bodyAllowedForStatus(rws.status) {
		return 0, http.ErrBodyNotAllowed
	}
	rws.wroteBytes += int64(len(dataB)) + int64(len(dataS)) // only one can be set
	if rws.sentContentLen != 0 && rws.wroteBytes > rws.sentContentLen {
		// TODO: send a RST_STREAM
		return 0, errors.New("http2: handler wrote more than declared Content-Length")
	}

	if dataB != nil {
		return rws.bw.Write(dataB)
	} else {
		return rws.bw.WriteString(dataS)
	}
}

func (w *http2responseWriter) handlerDone() {
	rws := w.rws
	dirty := rws.dirty
	rws.handlerDone = true
	w.Flush()
	w.rws = nil
	if !dirty {
		// Only recycle the pool if all prior Write calls to
		// the serverConn goroutine completed successfully. If
		// they returned earlier due to resets from the peer
		// there might still be write goroutines outstanding
		// from the serverConn referencing the rws memory. See
		// issue 20704.
		http2responseWriterStatePool.Put(rws)
	}
}

// Push errors.
var (
	http2ErrRecursivePush    = errors.New("http2: recursive push not allowed")
	http2ErrPushLimitReached = errors.New("http2: push would exceed peer's SETTINGS_MAX_CONCURRENT_STREAMS")
)

var _ http.Pusher = (*http2responseWriter)(nil)

func (w *http2responseWriter) Push(target string, opts *http.PushOptions) error {
	st := w.rws.stream
	sc := st.sc
	sc.serveG.checkNotOn()

	// No recursive pushes: "PUSH_PROMISE frames MUST only be sent on a peer-initiated stream."
	// http://tools.ietf.org/html/rfc7540#section-6.6
	if st.isPushed() {
		return http2ErrRecursivePush
	}

	if opts == nil {
		opts = new(http.PushOptions)
	}

	// Default options.
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Header == nil {
		opts.Header = http.Header{}
	}
	wantScheme := "http"
	if w.rws.req.TLS != nil {
		wantScheme = "https"
	}

	// Validate the request.
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme == "" {
		if !strings.HasPrefix(target, "/") {
			return fmt.Errorf("target must be an absolute URL or an absolute path: %q", target)
		}
		u.Scheme = wantScheme
		u.Host = w.rws.req.Host
	} else {
		if u.Scheme != wantScheme {
			return fmt.Errorf("cannot push URL with scheme %q from request with scheme %q", u.Scheme, wantScheme)
		}
		if u.Host == "" {
			return errors.New("URL must have a host")
		}
	}
	for k := range opts.Header {
		if strings.HasPrefix(k, ":") {
			return fmt.Errorf("promised request headers cannot include pseudo header %q", k)
		}
		// These headers are meaningful only if the request has a body,
		// but PUSH_PROMISE requests cannot have a body.
		// http://tools.ietf.org/html/rfc7540#section-8.2
		// Also disallow Host, since the promised URL must be absolute.
		if http2asciiEqualFold(k, "content-length") ||
			http2asciiEqualFold(k, "content-encoding") ||
			http2asciiEqualFold(k, "trailer") ||
			http2asciiEqualFold(k, "te") ||
			http2asciiEqualFold(k, "expect") ||
			http2asciiEqualFold(k, "host") {
			return fmt.Errorf("promised request headers cannot include %q", k)
		}
	}
	if err := http2checkValidHTTP2RequestHeaders(opts.Header); err != nil {
		return err
	}

	// The RFC effectively limits promised requests to GET and HEAD:
	// "Promised requests MUST be cacheable [GET, HEAD, or POST], and MUST be safe [GET or HEAD]"
	// http://tools.ietf.org/html/rfc7540#section-8.2
	if opts.Method != "GET" && opts.Method != "HEAD" {
		return fmt.Errorf("method %q must be GET or HEAD", opts.Method)
	}

	msg := &http2startPushRequest{
		parent: st,
		method: opts.Method,
		url:    u,
		header: http2cloneHeader(opts.Header),
		done:   http2errChanPool.Get().(chan error),
	}

	select {
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-st.cw:
		return http2errStreamClosed
	case sc.serveMsgCh <- msg:
	}

	select {
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-st.cw:
		return http2errStreamClosed
	case err := <-msg.done:
		http2errChanPool.Put(msg.done)
		return err
	}
}

type http2startPushRequest struct {
	parent *http2stream
	method string
	url    *url.URL
	header http.Header
	done   chan error
}

func (sc *http2serverConn) startPush(msg *http2startPushRequest) {
	sc.serveG.check()

	// http://tools.ietf.org/html/rfc7540#section-6.6.
	// PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
	// is in either the "open" or "half-closed (remote)" state.
	if msg.parent.state != http2stateOpen && msg.parent.state != http2stateHalfClosedRemote {
		// responseWriter.Push checks that the stream is peer-initiated.
		msg.done <- http2errStreamClosed
		return
	}

	// http://tools.ietf.org/html/rfc7540#section-6.6.
	if !sc.pushEnabled {
		msg.done <- http.ErrNotSupported
		return
	}

	// PUSH_PROMISE frames must be sent in increasing order by stream ID, so
	// we allocate an ID for the promised stream lazily, when the PUSH_PROMISE
	// is written. Once the ID is allocated, we start the request handler.
	allocatePromisedID := func() (uint32, error) {
		sc.serveG.check()

		// Check this again, just in case. Technically, we might have received
		// an updated SETTINGS by the time we got around to writing this frame.
		if !sc.pushEnabled {
			return 0, http.ErrNotSupported
		}
		// http://tools.ietf.org/html/rfc7540#section-6.5.2.
		if sc.curPushedStreams+1 > sc.clientMaxStreams {
			return 0, http2ErrPushLimitReached
		}

		// http://tools.ietf.org/html/rfc7540#section-5.1.1.
		// Streams initiated by the server MUST use even-numbered identifiers.
		// A server that is unable to establish a new stream identifier can send a GOAWAY
		// frame so that the client is forced to open a new connection for new streams.
		if sc.maxPushPromiseID+2 >= 1<<31 {
			sc.startGracefulShutdownInternal()
			return 0, http2ErrPushLimitReached
		}
		sc.maxPushPromiseID += 2
		promisedID := sc.maxPushPromiseID

		// http://tools.ietf.org/html/rfc7540#section-8.2.
		// Strictly speaking, the new stream should start in "reserved (local)", then
		// transition to "half closed (remote)" after sending the initial HEADERS, but
		// we start in "half closed (remote)" for simplicity.
		// See further comments at the definition of stateHalfClosedRemote.
		promised := sc.newStream(promisedID, msg.parent.id, http2stateHalfClosedRemote)
		rw, req, err := sc.newWriterAndRequestNoBody(promised, http2requestParam{
			method:    msg.method,
			scheme:    msg.url.Scheme,
			authority: msg.url.Host,
			path:      msg.url.RequestURI(),
			header:    http2cloneHeader(msg.header), // clone since handler runs concurrently with writing the PUSH_PROMISE
		})
		if err != nil {
			// Should not happen, since we've already validated msg.url.
			panic(fmt.Sprintf("newWriterAndRequestNoBody(%+v): %v", msg.url, err))
		}

		sc.curHandlers++
		go sc.runHandler(rw, req, sc.handler.ServeHTTP)
		return promisedID, nil
	}

	sc.writeFrame(http2FrameWriteRequest{
		write: &http2writePushPromise{
			streamID:           msg.parent.id,
			method:             msg.method,
			url:                msg.url,
			h:                  msg.header,
			allocatePromisedID: allocatePromisedID,
		},
		stream: msg.parent,
		done:   msg.done,
	})
}

// foreachHeaderElement splits v according to the "#rule" construction
// in RFC 7230 section 7 and calls fn for each non-empty element.
func http2foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}

// From http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.2
var http2connHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

// checkValidHTTP2RequestHeaders checks whether h is a valid HTTP/2 request,
// per RFC 7540 Section 8.1.2.2.
// The returned error is reported to users.
func http2checkValidHTTP2RequestHeaders(h http.Header) error {
	for _, k := range http2connHeaders {
		if _, ok := h[k]; ok {
			return fmt.Errorf("request header %q is not valid in HTTP/2", k)
		}
	}
	te := h["Te"]
	if len(te) > 0 && (len(te) > 1 || (te[0] != "trailers" && te[0] != "")) {
		return errors.New(`request header "TE" may only be "trailers" in HTTP/2`)
	}
	return nil
}

func http2new400Handler(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// h1ServerKeepAlivesDisabled reports whether hs has its keep-alives
// disabled. See comments on h1ServerShutdownChan above for why
// the code is written this way.
func http2h1ServerKeepAlivesDisabled(hs *Server) bool {
	var x interface{} = hs
	type I interface {
		doKeepAlives() bool
	}
	if hs, ok := x.(I); ok {
		return !hs.doKeepAlives()
	}
	return false
}

func (sc *http2serverConn) countError(name string, err error) error {
	if sc == nil || sc.srv == nil {
		return err
	}
	f := sc.srv.CountError
	if f == nil {
		return err
	}
	var typ string
	var code http2ErrCode
	switch e := err.(type) {
	case http2ConnectionError:
		typ = "conn"
		code = http2ErrCode(e)
	case http2StreamError:
		typ = "stream"
		code = http2ErrCode(e.Code)
	default:
		return err
	}
	codeStr := http2errCodeName[code]
	if codeStr == "" {
		codeStr = strconv.Itoa(int(code))
	}
	f(fmt.Sprintf("%s_%s_%s", typ, codeStr, name))
	return err
}

const (
	// transportDefaultConnFlow is how many connection-level flow control
	// tokens we give the server at start-up, past the default 64k.
	http2transportDefaultConnFlow = 1 << 30

	// transportDefaultStreamFlow is how many stream-level flow
	// control tokens we announce to the peer, and how many bytes
	// we buffer per stream.
	http2transportDefaultStreamFlow = 4 << 20

	http2defaultUserAgent = "Go-http-client/2.0"

	// initialMaxConcurrentStreams is a connections maxConcurrentStreams until
	// it's received servers initial SETTINGS frame, which corresponds with the
	// spec's minimum recommended value.
	http2initialMaxConcurrentStreams = 100

	// defaultMaxConcurrentStreams is a connections default maxConcurrentStreams
	// if the server doesn't include one in its initial SETTINGS frame.
	http2defaultMaxConcurrentStreams = 1000
)

// Transport is an HTTP/2 Transport.
//
// A Transport internally caches connections to servers. It is safe
// for concurrent use by multiple goroutines.
type http2Transport struct {
	// DialTLSContext specifies an optional dial function with context for
	// creating TLS connections for requests.
	//
	// If DialTLSContext and DialTLS is nil, tls.Dial is used.
	//
	// If the returned net.Conn has a ConnectionState method like tls.Conn,
	// it will be used to set http.Response.TLS.
	DialTLSContext func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for requests.
	//
	// If DialTLSContext and DialTLS is nil, tls.Dial is used.
	//
	// Deprecated: Use DialTLSContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialTLSContext takes priority.
	DialTLS func(network, addr string, cfg *tls.Config) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// ConnPool optionally specifies an alternate connection pool to use.
	// If nil, the default is used.
	ConnPool http2ClientConnPool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// AllowHTTP, if true, permits HTTP/2 requests using the insecure,
	// plain-text "http" scheme. Note that this does not enable h2c support.
	AllowHTTP bool

	// MaxHeaderListSize is the http2 SETTINGS_MAX_HEADER_LIST_SIZE to
	// send in the initial settings frame. It is how many bytes
	// of response headers are allowed. Unlike the http2 spec, zero here
	// means to use a default limit (currently 10MB). If you actually
	// want to advertise an unlimited value to the peer, Transport
	// interprets the highest possible value here (0xffffffff or 1<<32-1)
	// to mean no limit.
	MaxHeaderListSize uint32

	// MaxReadFrameSize is the http2 SETTINGS_MAX_FRAME_SIZE to send in the
	// initial settings frame. It is the size in bytes of the largest frame
	// payload that the sender is willing to receive. If 0, no setting is
	// sent, and the value is provided by the peer, which should be 16384
	// according to the spec:
	// https://datatracker.ietf.org/doc/html/rfc7540#section-6.5.2.
	// Values are bounded in the range 16k to 16M.
	MaxReadFrameSize uint32

	// MaxDecoderHeaderTableSize optionally specifies the http2
	// SETTINGS_HEADER_TABLE_SIZE to send in the initial settings frame. It
	// informs the remote endpoint of the maximum size of the header compression
	// table used to decode header blocks, in octets. If zero, the default value
	// of 4096 is used.
	MaxDecoderHeaderTableSize uint32

	// MaxEncoderHeaderTableSize optionally specifies an upper limit for the
	// header compression table used for encoding request headers. Received
	// SETTINGS_HEADER_TABLE_SIZE settings are capped at this limit. If zero,
	// the default value of 4096 is used.
	MaxEncoderHeaderTableSize uint32

	// StrictMaxConcurrentStreams controls whether the server's
	// SETTINGS_MAX_CONCURRENT_STREAMS should be respected
	// globally. If false, new TCP connections are created to the
	// server as needed to keep each under the per-connection
	// SETTINGS_MAX_CONCURRENT_STREAMS limit. If true, the
	// server's SETTINGS_MAX_CONCURRENT_STREAMS is interpreted as
	// a global limit and callers of RoundTrip block when needed,
	// waiting for their turn.
	StrictMaxConcurrentStreams bool

	// ReadIdleTimeout is the timeout after which a health check using ping
	// frame will be carried out if no frame is received on the connection.
	// Note that a ping response will is considered a received frame, so if
	// there is no other traffic on the connection, the health check will
	// be performed every ReadIdleTimeout interval.
	// If zero, no health check is performed.
	ReadIdleTimeout time.Duration

	// PingTimeout is the timeout after which the connection will be closed
	// if a response to Ping is not received.
	// Defaults to 15s.
	PingTimeout time.Duration

	// WriteByteTimeout is the timeout after which the connection will be
	// closed no data can be written to it. The timeout begins when data is
	// available to write, and is extended whenever any bytes are written.
	WriteByteTimeout time.Duration

	// CountError, if non-nil, is called on HTTP/2 transport errors.
	// It's intended to increment a metric for monitoring, such
	// as an expvar or Prometheus metric.
	// The errType consists of only ASCII word characters.
	CountError func(errType string)

	// t1, if non-nil, is the standard library Transport using
	// this transport. Its settings are used (but not its
	// RoundTrip method, etc).
	t1 *http.Transport

	connPoolOnce  sync.Once
	connPoolOrDef http2ClientConnPool // non-nil version of ConnPool
}

func (t *http2Transport) maxHeaderListSize() uint32 {
	if t.MaxHeaderListSize == 0 {
		return 10 << 20
	}
	if t.MaxHeaderListSize == 0xffffffff {
		return 0
	}
	return t.MaxHeaderListSize
}

func (t *http2Transport) maxFrameReadSize() uint32 {
	if t.MaxReadFrameSize == 0 {
		return 0 // use the default provided by the peer
	}
	if t.MaxReadFrameSize < http2minMaxFrameSize {
		return http2minMaxFrameSize
	}
	if t.MaxReadFrameSize > http2maxFrameSize {
		return http2maxFrameSize
	}
	return t.MaxReadFrameSize
}

func (t *http2Transport) disableCompression() bool {
	return t.DisableCompression || (t.t1 != nil && t.t1.DisableCompression)
}

func (t *http2Transport) pingTimeout() time.Duration {
	if t.PingTimeout == 0 {
		return 15 * time.Second
	}
	return t.PingTimeout

}

// ConfigureTransport configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns an error if t1 has already been HTTP/2-enabled.
//
// Use ConfigureTransports instead to configure the HTTP/2 Transport.
func http2ConfigureTransport(t1 *http.Transport) error {
	_, err := http2ConfigureTransports(t1)
	return err
}

// ConfigureTransports configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns a new HTTP/2 Transport for further configuration.
// It returns an error if t1 has already been HTTP/2-enabled.
func http2ConfigureTransports(t1 *http.Transport) (*http2Transport, error) {
	return http2configureTransports(t1)
}

func http2configureTransports(t1 *http.Transport) (*http2Transport, error) {
	connPool := new(http2clientConnPool)
	t2 := &http2Transport{
		ConnPool: http2noDialClientConnPool{connPool},
		t1:       t1,
	}
	connPool.t = t2
	if err := http2registerHTTPSProtocol(t1, http2noDialH2RoundTripper{t2}); err != nil {
		return nil, err
	}
	if t1.TLSClientConfig == nil {
		t1.TLSClientConfig = new(tls.Config)
	}
	if !http2strSliceContains(t1.TLSClientConfig.NextProtos, "h2") {
		t1.TLSClientConfig.NextProtos = append([]string{"h2"}, t1.TLSClientConfig.NextProtos...)
	}
	if !http2strSliceContains(t1.TLSClientConfig.NextProtos, "http/1.1") {
		t1.TLSClientConfig.NextProtos = append(t1.TLSClientConfig.NextProtos, "http/1.1")
	}
	upgradeFn := func(authority string, c *tls.Conn) http.RoundTripper {
		addr := http2authorityAddr("https", authority)
		if used, err := connPool.addConnIfNeeded(addr, t2, c); err != nil {
			go c.Close()
			return http2erringRoundTripper{err}
		} else if !used {
			// Turns out we don't need this c.
			// For example, two goroutines made requests to the same host
			// at the same time, both kicking off TCP dials. (since protocol
			// was unknown)
			go c.Close()
		}
		return t2
	}
	if m := t1.TLSNextProto; len(m) == 0 {
		t1.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{
			"h2": upgradeFn,
		}
	} else {
		m["h2"] = upgradeFn
	}
	return t2, nil
}

func (t *http2Transport) connPool() http2ClientConnPool {
	t.connPoolOnce.Do(t.initConnPool)
	return t.connPoolOrDef
}

func (t *http2Transport) initConnPool() {
	if t.ConnPool != nil {
		t.connPoolOrDef = t.ConnPool
	} else {
		t.connPoolOrDef = &http2clientConnPool{t: t}
	}
}

// ClientConn is the state of a single HTTP/2 client connection to an
// HTTP/2 server.
type http2ClientConn struct {
	t             *http2Transport
	tconn         net.Conn // usually *tls.Conn, except specialized impls
	tconnClosed   bool
	tlsState      *tls.ConnectionState // nil only for specialized impls
	reused        uint32               // whether conn is being reused; atomic
	singleUse     bool                 // whether being used for a single http.Request
	getConnCalled bool                 // used by clientConnPool

	// readLoop goroutine fields:
	readerDone chan struct{} // closed on error
	readerErr  error         // set before readerDone is closed

	idleTimeout time.Duration // or 0 for never
	idleTimer   *time.Timer

	mu              sync.Mutex   // guards following
	cond            *sync.Cond   // hold mu; broadcast on flow/closed changes
	flow            http2outflow // our conn-level flow control quota (cs.outflow is per stream)
	inflow          http2inflow  // peer's conn-level flow control
	doNotReuse      bool         // whether conn is marked to not be reused for any future requests
	closing         bool
	closed          bool
	seenSettings    bool                          // true if we've seen a settings frame, false otherwise
	wantSettingsAck bool                          // we sent a SETTINGS frame and haven't heard back
	goAway          *http2GoAwayFrame             // if non-nil, the GoAwayFrame we received
	goAwayDebug     string                        // goAway frame's debug data, retained as a string
	streams         map[uint32]*http2clientStream // client-initiated
	streamsReserved int                           // incr by ReserveNewRequest; decr on RoundTrip
	nextStreamID    uint32
	pendingRequests int                       // requests blocked and waiting to be sent because len(streams) == maxConcurrentStreams
	pings           map[[8]byte]chan struct{} // in flight ping data to notification channel
	br              *bufio.Reader
	lastActive      time.Time
	lastIdle        time.Time // time last idle
	// Settings from peer: (also guarded by wmu)
	maxFrameSize           uint32
	maxConcurrentStreams   uint32
	peerMaxHeaderListSize  uint64
	peerMaxHeaderTableSize uint32
	initialWindowSize      uint32

	// reqHeaderMu is a 1-element semaphore channel controlling access to sending new requests.
	// Write to reqHeaderMu to lock it, read from it to unlock.
	// Lock reqmu BEFORE mu or wmu.
	reqHeaderMu chan struct{}

	// wmu is held while writing.
	// Acquire BEFORE mu when holding both, to avoid blocking mu on network writes.
	// Only acquire both at the same time when changing peer settings.
	wmu  sync.Mutex
	bw   *bufio.Writer
	fr   *http2Framer
	werr error        // first write error that has occurred
	hbuf bytes.Buffer // HPACK encoder writes into this
	henc *hpack.Encoder
}

// clientStream is the state for a single HTTP/2 stream. One of these
// is created for each Transport.RoundTrip call.
type http2clientStream struct {
	cc *http2ClientConn

	// Fields of Request that we may access even after the response body is closed.
	ctx       context.Context
	reqCancel <-chan struct{}

	trace         *httptrace.ClientTrace // or nil
	ID            uint32
	bufPipe       http2pipe // buffered pipe with the flow-controlled response payload
	requestedGzip bool
	isHead        bool

	abortOnce sync.Once
	abort     chan struct{} // closed to signal stream should end immediately
	abortErr  error         // set if abort is closed

	peerClosed chan struct{} // closed when the peer sends an END_STREAM flag
	donec      chan struct{} // closed after the stream is in the closed state
	on100      chan struct{} // buffered; written to if a 100 is received

	respHeaderRecv chan struct{}  // closed when headers are received
	res            *http.Response // set if respHeaderRecv is closed

	flow        http2outflow // guarded by cc.mu
	inflow      http2inflow  // guarded by cc.mu
	bytesRemain int64        // -1 means unknown; owned by transportResponseBody.Read
	readErr     error        // sticky read error; owned by transportResponseBody.Read

	reqBody              io.ReadCloser
	reqBodyContentLength int64         // -1 means unknown
	reqBodyClosed        chan struct{} // guarded by cc.mu; non-nil on Close, closed when done

	// owned by writeRequest:
	sentEndStream bool // sent an END_STREAM flag to the peer
	sentHeaders   bool

	// owned by clientConnReadLoop:
	firstByte    bool  // got the first response byte
	pastHeaders  bool  // got first MetaHeadersFrame (actual headers)
	pastTrailers bool  // got optional second MetaHeadersFrame (trailers)
	num1xx       uint8 // number of 1xx responses seen
	readClosed   bool  // peer sent an END_STREAM flag
	readAborted  bool  // read loop reset the stream

	trailer    http.Header  // accumulated trailers
	resTrailer *http.Header // client's Response.Trailer
}

var http2got1xxFuncForTests func(int, textproto.MIMEHeader) error

// get1xxTraceFunc returns the value of request's httptrace.ClientTrace.Got1xxResponse func,
// if any. It returns nil if not set or if the Go version is too old.
func (cs *http2clientStream) get1xxTraceFunc() func(int, textproto.MIMEHeader) error {
	if fn := http2got1xxFuncForTests; fn != nil {
		return fn
	}
	return http2traceGot1xxResponseFunc(cs.trace)
}

func (cs *http2clientStream) abortStream(err error) {
	cs.cc.mu.Lock()
	defer cs.cc.mu.Unlock()
	cs.abortStreamLocked(err)
}

func (cs *http2clientStream) abortStreamLocked(err error) {
	cs.abortOnce.Do(func() {
		cs.abortErr = err
		close(cs.abort)
	})
	if cs.reqBody != nil {
		cs.closeReqBodyLocked()
	}
	// TODO(dneil): Clean up tests where cs.cc.cond is nil.
	if cs.cc.cond != nil {
		// Wake up writeRequestBody if it is waiting on flow control.
		cs.cc.cond.Broadcast()
	}
}

func (cs *http2clientStream) abortRequestBodyWrite() {
	cc := cs.cc
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cs.reqBody != nil && cs.reqBodyClosed == nil {
		cs.closeReqBodyLocked()
		cc.cond.Broadcast()
	}
}

func (cs *http2clientStream) closeReqBodyLocked() {
	if cs.reqBodyClosed != nil {
		return
	}
	cs.reqBodyClosed = make(chan struct{})
	reqBodyClosed := cs.reqBodyClosed
	go func() {
		cs.reqBody.Close()
		close(reqBodyClosed)
	}()
}

type http2stickyErrWriter struct {
	conn    net.Conn
	timeout time.Duration
	err     *error
}

func (sew http2stickyErrWriter) Write(p []byte) (n int, err error) {
	if *sew.err != nil {
		return 0, *sew.err
	}
	for {
		if sew.timeout != 0 {
			sew.conn.SetWriteDeadline(time.Now().Add(sew.timeout))
		}
		nn, err := sew.conn.Write(p[n:])
		n += nn
		if n < len(p) && nn > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			// Keep extending the deadline so long as we're making progress.
			continue
		}
		if sew.timeout != 0 {
			sew.conn.SetWriteDeadline(time.Time{})
		}
		*sew.err = err
		return n, err
	}
}

// noCachedConnError is the concrete type of ErrNoCachedConn, which
// needs to be detected by net/http regardless of whether it's its
// bundled version (in h2_bundle.go with a rewritten type name) or
// from a user's x/net/http2. As such, as it has a unique method name
// (IsHTTP2NoCachedConnError) that net/http sniffs for via func
// isNoCachedConnError.
type http2noCachedConnError struct{}

func (http2noCachedConnError) IsHTTP2NoCachedConnError() {}

func (http2noCachedConnError) Error() string { return "http2: no cached connection was available" }

// isNoCachedConnError reports whether err is of type noCachedConnError
// or its equivalent renamed type in net/http2's h2_bundle.go. Both types
// may coexist in the same running program.
func http2isNoCachedConnError(err error) bool {
	_, ok := err.(interface{ IsHTTP2NoCachedConnError() })
	return ok
}

var http2ErrNoCachedConn error = http2noCachedConnError{}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type http2RoundTripOpt struct {
	// OnlyCachedConn controls whether RoundTripOpt may
	// create a new TCP connection. If set true and
	// no cached connection is available, RoundTripOpt
	// will return ErrNoCachedConn.
	OnlyCachedConn bool
}

func (t *http2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RoundTripOpt(req, http2RoundTripOpt{})
}

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func http2authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		host = authority
		port = ""
	}
	if port == "" { // authority's port was empty
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

var http2retryBackoffHook func(time.Duration) *time.Timer

func http2backoffNewTimer(d time.Duration) *time.Timer {
	if http2retryBackoffHook != nil {
		return http2retryBackoffHook(d)
	}
	return time.NewTimer(d)
}

// RoundTripOpt is like RoundTrip, but takes options.
func (t *http2Transport) RoundTripOpt(req *http.Request, opt http2RoundTripOpt) (*http.Response, error) {
	if !(req.URL.Scheme == "https" || (req.URL.Scheme == "http" && t.AllowHTTP)) {
		return nil, errors.New("http2: unsupported scheme")
	}

	addr := http2authorityAddr(req.URL.Scheme, req.URL.Host)
	for retry := 0; ; retry++ {
		cc, err := t.connPool().GetClientConn(req, addr)
		if err != nil {
			t.vlogf("http2: Transport failed to get client conn for %s: %v", addr, err)
			return nil, err
		}
		reused := !atomic.CompareAndSwapUint32(&cc.reused, 0, 1)
		http2traceGotConn(req, cc, reused)
		res, err := cc.RoundTrip(req)
		if err != nil && retry <= 6 {
			roundTripErr := err
			if req, err = http2shouldRetryRequest(req, err); err == nil {
				// After the first retry, do exponential backoff with 10% jitter.
				if retry == 0 {
					t.vlogf("RoundTrip retrying after failure: %v", roundTripErr)
					continue
				}
				backoff := float64(uint(1) << (uint(retry) - 1))
				backoff += backoff * (0.1 * mathrand.Float64())
				d := time.Second * time.Duration(backoff)
				timer := http2backoffNewTimer(d)
				select {
				case <-timer.C:
					t.vlogf("RoundTrip retrying after failure: %v", roundTripErr)
					continue
				case <-req.Context().Done():
					timer.Stop()
					err = req.Context().Err()
				}
			}
		}
		if err != nil {
			t.vlogf("RoundTrip failure: %v", err)
			return nil, err
		}
		return res, nil
	}
}

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle.
// It does not interrupt any connections currently in use.
func (t *http2Transport) CloseIdleConnections() {
	if cp, ok := t.connPool().(http2clientConnPoolIdleCloser); ok {
		cp.closeIdleConnections()
	}
}

var (
	http2errClientConnClosed    = errors.New("http2: client conn is closed")
	http2errClientConnUnusable  = errors.New("http2: client conn not usable")
	http2errClientConnGotGoAway = errors.New("http2: Transport received Server's graceful shutdown GOAWAY")
)

// shouldRetryRequest is called by RoundTrip when a request fails to get
// response headers. It is always called with a non-nil error.
// It returns either a request to retry (either the same request, or a
// modified clone), or an error if the request can't be replayed.
func http2shouldRetryRequest(req *http.Request, err error) (*http.Request, error) {
	if !http2canRetryError(err) {
		return nil, err
	}
	// If the Body is nil (or http.NoBody), it's safe to reuse
	// this request and its Body.
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}

	// If the request body can be reset back to its original
	// state via the optional req.GetBody, do that.
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq := *req
		newReq.Body = body
		return &newReq, nil
	}

	// The Request.Body can't reset back to the beginning, but we
	// don't seem to have started to read from it yet, so reuse
	// the request directly.
	if err == http2errClientConnUnusable {
		return req, nil
	}

	return nil, fmt.Errorf("http2: Transport: cannot retry err [%v] after Request.Body was written; define Request.GetBody to avoid this error", err)
}

func http2canRetryError(err error) bool {
	if err == http2errClientConnUnusable || err == http2errClientConnGotGoAway {
		return true
	}
	if se, ok := err.(http2StreamError); ok {
		if se.Code == http2ErrCodeProtocol && se.Cause == http2errFromPeer {
			// See golang/go#47635, golang/go#42777
			return true
		}
		return se.Code == http2ErrCodeRefusedStream
	}
	return false
}

func (t *http2Transport) dialClientConn(ctx context.Context, addr string, singleUse bool) (*http2ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tconn, err := t.dialTLS(ctx, "tcp", addr, t.newTLSConfig(host))
	if err != nil {
		return nil, err
	}
	return t.newClientConn(tconn, singleUse)
}

func (t *http2Transport) newTLSConfig(host string) *tls.Config {
	cfg := new(tls.Config)
	if t.TLSClientConfig != nil {
		*cfg = *t.TLSClientConfig.Clone()
	}
	if !http2strSliceContains(cfg.NextProtos, http2NextProtoTLS) {
		cfg.NextProtos = append([]string{http2NextProtoTLS}, cfg.NextProtos...)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

func (t *http2Transport) dialTLS(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if t.DialTLSContext != nil {
		return t.DialTLSContext(ctx, network, addr, tlsCfg)
	} else if t.DialTLS != nil {
		return t.DialTLS(network, addr, tlsCfg)
	}

	tlsCn, err := t.dialTLSWithContext(ctx, network, addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	state := tlsCn.ConnectionState()
	if p := state.NegotiatedProtocol; p != http2NextProtoTLS {
		return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2NextProtoTLS)
	}
	if !state.NegotiatedProtocolIsMutual {
		return nil, errors.New("http2: could not negotiate protocol mutually")
	}
	return tlsCn, nil
}

// disableKeepAlives reports whether connections should be closed as
// soon as possible after handling the first request.
func (t *http2Transport) disableKeepAlives() bool {
	return t.t1 != nil && t.t1.DisableKeepAlives
}

func (t *http2Transport) expectContinueTimeout() time.Duration {
	if t.t1 == nil {
		return 0
	}
	return t.t1.ExpectContinueTimeout
}

func (t *http2Transport) maxDecoderHeaderTableSize() uint32 {
	if v := t.MaxDecoderHeaderTableSize; v > 0 {
		return v
	}
	return http2initialHeaderTableSize
}

func (t *http2Transport) maxEncoderHeaderTableSize() uint32 {
	if v := t.MaxEncoderHeaderTableSize; v > 0 {
		return v
	}
	return http2initialHeaderTableSize
}

func (t *http2Transport) NewClientConn(c net.Conn) (*http2ClientConn, error) {
	return t.newClientConn(c, t.disableKeepAlives())
}

func (t *http2Transport) newClientConn(c net.Conn, singleUse bool) (*http2ClientConn, error) {
	cc := &http2ClientConn{
		t:                     t,
		tconn:                 c,
		readerDone:            make(chan struct{}),
		nextStreamID:          1,
		maxFrameSize:          16 << 10,                         // spec default
		initialWindowSize:     65535,                            // spec default
		maxConcurrentStreams:  http2initialMaxConcurrentStreams, // "infinite", per spec. Use a smaller value until we have received server settings.
		peerMaxHeaderListSize: 0xffffffffffffffff,               // "infinite", per spec. Use 2^64-1 instead.
		streams:               make(map[uint32]*http2clientStream),
		singleUse:             singleUse,
		wantSettingsAck:       true,
		pings:                 make(map[[8]byte]chan struct{}),
		reqHeaderMu:           make(chan struct{}, 1),
	}
	if d := t.idleConnTimeout(); d != 0 {
		cc.idleTimeout = d
		cc.idleTimer = time.AfterFunc(d, cc.onIdleTimeout)
	}
	if http2VerboseLogs {
		t.vlogf("http2: Transport creating client conn %p to %v", cc, c.RemoteAddr())
	}

	cc.cond = sync.NewCond(&cc.mu)
	cc.flow.add(int32(http2initialWindowSize))

	// TODO: adjust this writer size to account for frame size +
	// MTU + crypto/tls record padding.
	cc.bw = bufio.NewWriter(http2stickyErrWriter{
		conn:    c,
		timeout: t.WriteByteTimeout,
		err:     &cc.werr,
	})
	cc.br = bufio.NewReader(c)
	cc.fr = http2NewFramer(cc.bw, cc.br)
	if t.maxFrameReadSize() != 0 {
		cc.fr.SetMaxReadFrameSize(t.maxFrameReadSize())
	}
	if t.CountError != nil {
		cc.fr.countError = t.CountError
	}
	maxHeaderTableSize := t.maxDecoderHeaderTableSize()
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(maxHeaderTableSize, nil)
	cc.fr.MaxHeaderListSize = t.maxHeaderListSize()

	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(t.maxEncoderHeaderTableSize())
	cc.peerMaxHeaderTableSize = http2initialHeaderTableSize

	if t.AllowHTTP {
		cc.nextStreamID = 3
	}

	if cs, ok := c.(http2connectionStater); ok {
		state := cs.ConnectionState()
		cc.tlsState = &state
	}

	initialSettings := []http2Setting{
		{ID: http2SettingEnablePush, Val: 0},
		{ID: http2SettingInitialWindowSize, Val: http2transportDefaultStreamFlow},
	}
	if max := t.maxFrameReadSize(); max != 0 {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxFrameSize, Val: max})
	}
	if max := t.maxHeaderListSize(); max != 0 {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxHeaderListSize, Val: max})
	}
	if maxHeaderTableSize != http2initialHeaderTableSize {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingHeaderTableSize, Val: maxHeaderTableSize})
	}

	cc.bw.Write(http2clientPreface)
	cc.fr.WriteSettings(initialSettings...)
	cc.fr.WriteWindowUpdate(0, http2transportDefaultConnFlow)
	cc.inflow.init(http2transportDefaultConnFlow + http2initialWindowSize)
	cc.bw.Flush()
	if cc.werr != nil {
		cc.Close()
		return nil, cc.werr
	}

	go cc.readLoop()
	return cc, nil
}

func (cc *http2ClientConn) healthCheck() {
	pingTimeout := cc.t.pingTimeout()
	// We don't need to periodically ping in the health check, because the readLoop of ClientConn will
	// trigger the healthCheck again if there is no frame received.
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	cc.vlogf("http2: Transport sending health check")
	err := cc.Ping(ctx)
	if err != nil {
		cc.vlogf("http2: Transport health check failure: %v", err)
		cc.closeForLostPing()
	} else {
		cc.vlogf("http2: Transport health check success")
	}
}

// SetDoNotReuse marks cc as not reusable for future HTTP requests.
func (cc *http2ClientConn) SetDoNotReuse() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.doNotReuse = true
}

func (cc *http2ClientConn) setGoAway(f *http2GoAwayFrame) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	old := cc.goAway
	cc.goAway = f

	// Merge the previous and current GoAway error frames.
	if cc.goAwayDebug == "" {
		cc.goAwayDebug = string(f.DebugData())
	}
	if old != nil && old.ErrCode != http2ErrCodeNo {
		cc.goAway.ErrCode = old.ErrCode
	}
	last := f.LastStreamID
	for streamID, cs := range cc.streams {
		if streamID > last {
			cs.abortStreamLocked(http2errClientConnGotGoAway)
		}
	}
}

// CanTakeNewRequest reports whether the connection can take a new request,
// meaning it has not been closed or received or sent a GOAWAY.
//
// If the caller is going to immediately make a new request on this
// connection, use ReserveNewRequest instead.
func (cc *http2ClientConn) CanTakeNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.canTakeNewRequestLocked()
}

// ReserveNewRequest is like CanTakeNewRequest but also reserves a
// concurrent stream in cc. The reservation is decremented on the
// next call to RoundTrip.
func (cc *http2ClientConn) ReserveNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if st := cc.idleStateLocked(); !st.canTakeNewRequest {
		return false
	}
	cc.streamsReserved++
	return true
}

// ClientConnState describes the state of a ClientConn.
type http2ClientConnState struct {
	// Closed is whether the connection is closed.
	Closed bool

	// Closing is whether the connection is in the process of
	// closing. It may be closing due to shutdown, being a
	// single-use connection, being marked as DoNotReuse, or
	// having received a GOAWAY frame.
	Closing bool

	// StreamsActive is how many streams are active.
	StreamsActive int

	// StreamsReserved is how many streams have been reserved via
	// ClientConn.ReserveNewRequest.
	StreamsReserved int

	// StreamsPending is how many requests have been sent in excess
	// of the peer's advertised MaxConcurrentStreams setting and
	// are waiting for other streams to complete.
	StreamsPending int

	// MaxConcurrentStreams is how many concurrent streams the
	// peer advertised as acceptable. Zero means no SETTINGS
	// frame has been received yet.
	MaxConcurrentStreams uint32

	// LastIdle, if non-zero, is when the connection last
	// transitioned to idle state.
	LastIdle time.Time
}

// State returns a snapshot of cc's state.
func (cc *http2ClientConn) State() http2ClientConnState {
	cc.wmu.Lock()
	maxConcurrent := cc.maxConcurrentStreams
	if !cc.seenSettings {
		maxConcurrent = 0
	}
	cc.wmu.Unlock()

	cc.mu.Lock()
	defer cc.mu.Unlock()
	return http2ClientConnState{
		Closed:               cc.closed,
		Closing:              cc.closing || cc.singleUse || cc.doNotReuse || cc.goAway != nil,
		StreamsActive:        len(cc.streams),
		StreamsReserved:      cc.streamsReserved,
		StreamsPending:       cc.pendingRequests,
		LastIdle:             cc.lastIdle,
		MaxConcurrentStreams: maxConcurrent,
	}
}

// clientConnIdleState describes the suitability of a client
// connection to initiate a new RoundTrip request.
type http2clientConnIdleState struct {
	canTakeNewRequest bool
}

func (cc *http2ClientConn) idleState() http2clientConnIdleState {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.idleStateLocked()
}

func (cc *http2ClientConn) idleStateLocked() (st http2clientConnIdleState) {
	if cc.singleUse && cc.nextStreamID > 1 {
		return
	}
	var maxConcurrentOkay bool
	if cc.t.StrictMaxConcurrentStreams {
		// We'll tell the caller we can take a new request to
		// prevent the caller from dialing a new TCP
		// connection, but then we'll block later before
		// writing it.
		maxConcurrentOkay = true
	} else {
		maxConcurrentOkay = int64(len(cc.streams)+cc.streamsReserved+1) <= int64(cc.maxConcurrentStreams)
	}

	st.canTakeNewRequest = cc.goAway == nil && !cc.closed && !cc.closing && maxConcurrentOkay &&
		!cc.doNotReuse &&
		int64(cc.nextStreamID)+2*int64(cc.pendingRequests) < math.MaxInt32 &&
		!cc.tooIdleLocked()
	return
}

func (cc *http2ClientConn) canTakeNewRequestLocked() bool {
	st := cc.idleStateLocked()
	return st.canTakeNewRequest
}

// tooIdleLocked reports whether this connection has been been sitting idle
// for too much wall time.
func (cc *http2ClientConn) tooIdleLocked() bool {
	// The Round(0) strips the monontonic clock reading so the
	// times are compared based on their wall time. We don't want
	// to reuse a connection that's been sitting idle during
	// VM/laptop suspend if monotonic time was also frozen.
	return cc.idleTimeout != 0 && !cc.lastIdle.IsZero() && time.Since(cc.lastIdle.Round(0)) > cc.idleTimeout
}

// onIdleTimeout is called from a time.AfterFunc goroutine. It will
// only be called when we're idle, but because we're coming from a new
// goroutine, there could be a new request coming in at the same time,
// so this simply calls the synchronized closeIfIdle to shut down this
// connection. The timer could just call closeIfIdle, but this is more
// clear.
func (cc *http2ClientConn) onIdleTimeout() {
	cc.closeIfIdle()
}

func (cc *http2ClientConn) closeConn() {
	t := time.AfterFunc(250*time.Millisecond, cc.forceCloseConn)
	defer t.Stop()
	cc.tconn.Close()
}

// A tls.Conn.Close can hang for a long time if the peer is unresponsive.
// Try to shut it down more aggressively.
func (cc *http2ClientConn) forceCloseConn() {
	tc, ok := cc.tconn.(*tls.Conn)
	if !ok {
		return
	}
	if nc := http2tlsUnderlyingConn(tc); nc != nil {
		nc.Close()
	}
}

func (cc *http2ClientConn) closeIfIdle() {
	cc.mu.Lock()
	if len(cc.streams) > 0 || cc.streamsReserved > 0 {
		cc.mu.Unlock()
		return
	}
	cc.closed = true
	nextID := cc.nextStreamID
	// TODO: do clients send GOAWAY too? maybe? Just Close:
	cc.mu.Unlock()

	if http2VerboseLogs {
		cc.vlogf("http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)", cc, cc.singleUse, nextID-2)
	}
	cc.closeConn()
}

func (cc *http2ClientConn) isDoNotReuseAndIdle() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.doNotReuse && len(cc.streams) == 0
}

var http2shutdownEnterWaitStateHook = func() {}

// Shutdown gracefully closes the client connection, waiting for running streams to complete.
func (cc *http2ClientConn) Shutdown(ctx context.Context) error {
	if err := cc.sendGoAway(); err != nil {
		return err
	}
	// Wait for all in-flight streams to complete or connection to close
	done := make(chan struct{})
	cancelled := false // guarded by cc.mu
	go func() {
		cc.mu.Lock()
		defer cc.mu.Unlock()
		for {
			if len(cc.streams) == 0 || cc.closed {
				cc.closed = true
				close(done)
				break
			}
			if cancelled {
				break
			}
			cc.cond.Wait()
		}
	}()
	http2shutdownEnterWaitStateHook()
	select {
	case <-done:
		cc.closeConn()
		return nil
	case <-ctx.Done():
		cc.mu.Lock()
		// Free the goroutine above
		cancelled = true
		cc.cond.Broadcast()
		cc.mu.Unlock()
		return ctx.Err()
	}
}

func (cc *http2ClientConn) sendGoAway() error {
	cc.mu.Lock()
	closing := cc.closing
	cc.closing = true
	maxStreamID := cc.nextStreamID
	cc.mu.Unlock()
	if closing {
		// GOAWAY sent already
		return nil
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	// Send a graceful shutdown frame to server
	if err := cc.fr.WriteGoAway(maxStreamID, http2ErrCodeNo, nil); err != nil {
		return err
	}
	if err := cc.bw.Flush(); err != nil {
		return err
	}
	// Prevent new requests
	return nil
}

// closes the client connection immediately. In-flight requests are interrupted.
// err is sent to streams.
func (cc *http2ClientConn) closeForError(err error) {
	cc.mu.Lock()
	cc.closed = true
	for _, cs := range cc.streams {
		cs.abortStreamLocked(err)
	}
	cc.cond.Broadcast()
	cc.mu.Unlock()
	cc.closeConn()
}

// Close closes the client connection immediately.
//
// In-flight requests are interrupted. For a graceful shutdown, use Shutdown instead.
func (cc *http2ClientConn) Close() error {
	err := errors.New("http2: client connection force closed via ClientConn.Close")
	cc.closeForError(err)
	return nil
}

// closes the client connection immediately. In-flight requests are interrupted.
func (cc *http2ClientConn) closeForLostPing() {
	err := errors.New("http2: client connection lost")
	if f := cc.t.CountError; f != nil {
		f("conn_close_lost_ping")
	}
	cc.closeForError(err)
}

// errRequestCanceled is a copy of net/http's errRequestCanceled because it's not
// exported. At least they'll be DeepEqual for h1-vs-h2 comparisons tests.
var http2errRequestCanceled = errors.New("net/http: request canceled")

func http2commaSeparatedTrailers(req *http.Request) (string, error) {
	keys := make([]string, 0, len(req.Trailer))
	for k := range req.Trailer {
		k = http2canonicalHeader(k)
		switch k {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return "", fmt.Errorf("invalid Trailer key %q", k)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return strings.Join(keys, ","), nil
	}
	return "", nil
}

func (cc *http2ClientConn) responseHeaderTimeout() time.Duration {
	if cc.t.t1 != nil {
		return cc.t.t1.ResponseHeaderTimeout
	}
	// No way to do this (yet?) with just an http2.Transport. Probably
	// no need. Request.Cancel this is the new way. We only need to support
	// this for compatibility with the old http.Transport fields when
	// we're doing transparent http2.
	return 0
}

// checkConnHeaders checks whether req has any invalid connection-level headers.
// per RFC 7540 section 8.1.2.2: Connection-Specific Header Fields.
// Certain headers are special-cased as okay but not transmitted later.
func http2checkConnHeaders(req *http.Request) error {
	if v := req.Header.Get("Upgrade"); v != "" {
		return fmt.Errorf("http2: invalid Upgrade request header: %q", req.Header["Upgrade"])
	}
	if vv := req.Header["Transfer-Encoding"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("http2: invalid Transfer-Encoding request header: %q", vv)
	}
	if vv := req.Header["Connection"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && !http2asciiEqualFold(vv[0], "close") && !http2asciiEqualFold(vv[0], "keep-alive")) {
		return fmt.Errorf("http2: invalid Connection request header: %q", vv)
	}
	return nil
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func http2actualContentLength(req *http.Request) int64 {
	if req.Body == nil || req.Body == http.NoBody {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

func (cc *http2ClientConn) decrStreamReservations() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.decrStreamReservationsLocked()
}

func (cc *http2ClientConn) decrStreamReservationsLocked() {
	if cc.streamsReserved > 0 {
		cc.streamsReserved--
	}
}

func (cc *http2ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	cs := &http2clientStream{
		cc:                   cc,
		ctx:                  ctx,
		reqCancel:            req.Cancel,
		isHead:               req.Method == "HEAD",
		reqBody:              req.Body,
		reqBodyContentLength: http2actualContentLength(req),
		trace:                httptrace.ContextClientTrace(ctx),
		peerClosed:           make(chan struct{}),
		abort:                make(chan struct{}),
		respHeaderRecv:       make(chan struct{}),
		donec:                make(chan struct{}),
	}
	go cs.doRequest(req)

	waitDone := func() error {
		select {
		case <-cs.donec:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-cs.reqCancel:
			return http2errRequestCanceled
		}
	}

	handleResponseHeaders := func() (*http.Response, error) {
		res := cs.res
		if res.StatusCode > 299 {
			// On error or status code 3xx, 4xx, 5xx, etc abort any
			// ongoing write, assuming that the server doesn't care
			// about our request body. If the server replied with 1xx or
			// 2xx, however, then assume the server DOES potentially
			// want our body (e.g. full-duplex streaming:
			// golang.org/issue/13444). If it turns out the server
			// doesn't, they'll RST_STREAM us soon enough. This is a
			// heuristic to avoid adding knobs to Transport. Hopefully
			// we can keep it.
			cs.abortRequestBodyWrite()
		}
		res.Request = req
		res.TLS = cc.tlsState
		if res.Body == http2noBody && http2actualContentLength(req) == 0 {
			// If there isn't a request or response body still being
			// written, then wait for the stream to be closed before
			// RoundTrip returns.
			if err := waitDone(); err != nil {
				return nil, err
			}
		}
		return res, nil
	}

	cancelRequest := func(cs *http2clientStream, err error) error {
		cs.cc.mu.Lock()
		bodyClosed := cs.reqBodyClosed
		cs.cc.mu.Unlock()
		// Wait for the request body to be closed.
		//
		// If nothing closed the body before now, abortStreamLocked
		// will have started a goroutine to close it.
		//
		// Closing the body before returning avoids a race condition
		// with net/http checking its readTrackingBody to see if the
		// body was read from or closed. See golang/go#60041.
		//
		// The body is closed in a separate goroutine without the
		// connection mutex held, but dropping the mutex before waiting
		// will keep us from holding it indefinitely if the body
		// close is slow for some reason.
		if bodyClosed != nil {
			<-bodyClosed
		}
		return err
	}

	for {
		select {
		case <-cs.respHeaderRecv:
			return handleResponseHeaders()
		case <-cs.abort:
			select {
			case <-cs.respHeaderRecv:
				// If both cs.respHeaderRecv and cs.abort are signaling,
				// pick respHeaderRecv. The server probably wrote the
				// response and immediately reset the stream.
				// golang.org/issue/49645
				return handleResponseHeaders()
			default:
				waitDone()
				return nil, cs.abortErr
			}
		case <-ctx.Done():
			err := ctx.Err()
			cs.abortStream(err)
			return nil, cancelRequest(cs, err)
		case <-cs.reqCancel:
			cs.abortStream(http2errRequestCanceled)
			return nil, cancelRequest(cs, http2errRequestCanceled)
		}
	}
}

// doRequest runs for the duration of the request lifetime.
//
// It sends the request and performs post-request cleanup (closing Request.Body, etc.).
func (cs *http2clientStream) doRequest(req *http.Request) {
	err := cs.writeRequest(req)
	cs.cleanupWriteRequest(err)
}

// writeRequest sends a request.
//
// It returns nil after the request is written, the response read,
// and the request stream is half-closed by the peer.
//
// It returns non-nil if the request ends otherwise.
// If the returned error is StreamError, the error Code may be used in resetting the stream.
func (cs *http2clientStream) writeRequest(req *http.Request) (err error) {
	cc := cs.cc
	ctx := cs.ctx

	if err := http2checkConnHeaders(req); err != nil {
		return err
	}

	// Acquire the new-request lock by writing to reqHeaderMu.
	// This lock guards the critical section covering allocating a new stream ID
	// (requires mu) and creating the stream (requires wmu).
	if cc.reqHeaderMu == nil {
		panic("RoundTrip on uninitialized ClientConn") // for tests
	}
	select {
	case cc.reqHeaderMu <- struct{}{}:
	case <-cs.reqCancel:
		return http2errRequestCanceled
	case <-ctx.Done():
		return ctx.Err()
	}

	cc.mu.Lock()
	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
	}
	cc.decrStreamReservationsLocked()
	if err := cc.awaitOpenSlotForStreamLocked(cs); err != nil {
		cc.mu.Unlock()
		<-cc.reqHeaderMu
		return err
	}
	cc.addStreamLocked(cs) // assigns stream ID
	if http2isConnectionCloseRequest(req) {
		cc.doNotReuse = true
	}
	cc.mu.Unlock()

	// TODO(bradfitz): this is a copy of the logic in net/http. Unify somewhere?
	if !cc.t.disableCompression() &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		!cs.isHead {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		cs.requestedGzip = true
	}

	continueTimeout := cc.t.expectContinueTimeout()
	if continueTimeout != 0 {
		if !httpguts.HeaderValuesContainsToken(req.Header["Expect"], "100-continue") {
			continueTimeout = 0
		} else {
			cs.on100 = make(chan struct{}, 1)
		}
	}

	// Past this point (where we send request headers), it is possible for
	// RoundTrip to return successfully. Since the RoundTrip contract permits
	// the caller to "mutate or reuse" the Request after closing the Response's Body,
	// we must take care when referencing the Request from here on.
	err = cs.encodeAndWriteHeaders(req)
	<-cc.reqHeaderMu
	if err != nil {
		return err
	}

	hasBody := cs.reqBodyContentLength != 0
	if !hasBody {
		cs.sentEndStream = true
	} else {
		if continueTimeout != 0 {
			http2traceWait100Continue(cs.trace)
			timer := time.NewTimer(continueTimeout)
			select {
			case <-timer.C:
				err = nil
			case <-cs.on100:
				err = nil
			case <-cs.abort:
				err = cs.abortErr
			case <-ctx.Done():
				err = ctx.Err()
			case <-cs.reqCancel:
				err = http2errRequestCanceled
			}
			timer.Stop()
			if err != nil {
				http2traceWroteRequest(cs.trace, err)
				return err
			}
		}

		if err = cs.writeRequestBody(req); err != nil {
			if err != http2errStopReqBodyWrite {
				http2traceWroteRequest(cs.trace, err)
				return err
			}
		} else {
			cs.sentEndStream = true
		}
	}

	http2traceWroteRequest(cs.trace, err)

	var respHeaderTimer <-chan time.Time
	var respHeaderRecv chan struct{}
	if d := cc.responseHeaderTimeout(); d != 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		respHeaderTimer = timer.C
		respHeaderRecv = cs.respHeaderRecv
	}
	// Wait until the peer half-closes its end of the stream,
	// or until the request is aborted (via context, error, or otherwise),
	// whichever comes first.
	for {
		select {
		case <-cs.peerClosed:
			return nil
		case <-respHeaderTimer:
			return http2errTimeout
		case <-respHeaderRecv:
			respHeaderRecv = nil
			respHeaderTimer = nil // keep waiting for END_STREAM
		case <-cs.abort:
			return cs.abortErr
		case <-ctx.Done():
			return ctx.Err()
		case <-cs.reqCancel:
			return http2errRequestCanceled
		}
	}
}

func (cs *http2clientStream) encodeAndWriteHeaders(req *http.Request) error {
	cc := cs.cc
	ctx := cs.ctx

	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	// If the request was canceled while waiting for cc.mu, just quit.
	select {
	case <-cs.abort:
		return cs.abortErr
	case <-ctx.Done():
		return ctx.Err()
	case <-cs.reqCancel:
		return http2errRequestCanceled
	default:
	}

	// Encode headers.
	//
	// we send: HEADERS{1}, CONTINUATION{0,} + DATA{0,} (DATA is
	// sent by writeRequestBody below, along with any Trailers,
	// again in form HEADERS{1}, CONTINUATION{0,})
	trailers, err := http2commaSeparatedTrailers(req)
	if err != nil {
		return err
	}
	hasTrailers := trailers != ""
	contentLen := http2actualContentLength(req)
	hasBody := contentLen != 0
	hdrs, err := cc.encodeHeaders(req, cs.requestedGzip, trailers, contentLen)
	if err != nil {
		return err
	}

	// Write the request.
	endStream := !hasBody && !hasTrailers
	cs.sentHeaders = true
	err = cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)
	http2traceWroteHeaders(cs.trace)
	return err
}

// cleanupWriteRequest performs post-request tasks.
//
// If err (the result of writeRequest) is non-nil and the stream is not closed,
// cleanupWriteRequest will send a reset to the peer.
func (cs *http2clientStream) cleanupWriteRequest(err error) {
	cc := cs.cc

	if cs.ID == 0 {
		// We were canceled before creating the stream, so return our reservation.
		cc.decrStreamReservations()
	}

	// TODO: write h12Compare test showing whether
	// Request.Body is closed by the Transport,
	// and in multiple cases: server replies <=299 and >299
	// while still writing request body
	cc.mu.Lock()
	mustCloseBody := false
	if cs.reqBody != nil && cs.reqBodyClosed == nil {
		mustCloseBody = true
		cs.reqBodyClosed = make(chan struct{})
	}
	bodyClosed := cs.reqBodyClosed
	cc.mu.Unlock()
	if mustCloseBody {
		cs.reqBody.Close()
		close(bodyClosed)
	}
	if bodyClosed != nil {
		<-bodyClosed
	}

	if err != nil && cs.sentEndStream {
		// If the connection is closed immediately after the response is read,
		// we may be aborted before finishing up here. If the stream was closed
		// cleanly on both sides, there is no error.
		select {
		case <-cs.peerClosed:
			err = nil
		default:
		}
	}
	if err != nil {
		cs.abortStream(err) // possibly redundant, but harmless
		if cs.sentHeaders {
			if se, ok := err.(http2StreamError); ok {
				if se.Cause != http2errFromPeer {
					cc.writeStreamReset(cs.ID, se.Code, err)
				}
			} else {
				cc.writeStreamReset(cs.ID, http2ErrCodeCancel, err)
			}
		}
		cs.bufPipe.CloseWithError(err) // no-op if already closed
	} else {
		if cs.sentHeaders && !cs.sentEndStream {
			cc.writeStreamReset(cs.ID, http2ErrCodeNo, nil)
		}
		cs.bufPipe.CloseWithError(http2errRequestCanceled)
	}
	if cs.ID != 0 {
		cc.forgetStreamID(cs.ID)
	}

	cc.wmu.Lock()
	werr := cc.werr
	cc.wmu.Unlock()
	if werr != nil {
		cc.Close()
	}

	close(cs.donec)
}

// awaitOpenSlotForStreamLocked waits until len(streams) < maxConcurrentStreams.
// Must hold cc.mu.
func (cc *http2ClientConn) awaitOpenSlotForStreamLocked(cs *http2clientStream) error {
	for {
		cc.lastActive = time.Now()
		if cc.closed || !cc.canTakeNewRequestLocked() {
			return http2errClientConnUnusable
		}
		cc.lastIdle = time.Time{}
		if int64(len(cc.streams)) < int64(cc.maxConcurrentStreams) {
			return nil
		}
		cc.pendingRequests++
		cc.cond.Wait()
		cc.pendingRequests--
		select {
		case <-cs.abort:
			return cs.abortErr
		default:
		}
	}
}

// requires cc.wmu be held
func (cc *http2ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	first := true // first frame written (HEADERS is first, then CONTINUATION)
	for len(hdrs) > 0 && cc.werr == nil {
		chunk := hdrs
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		hdrs = hdrs[len(chunk):]
		endHeaders := len(hdrs) == 0
		if first {
			cc.fr.WriteHeaders(http2HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndStream:     endStream,
				EndHeaders:    endHeaders,
			})
			first = false
		} else {
			cc.fr.WriteContinuation(streamID, endHeaders, chunk)
		}
	}
	cc.bw.Flush()
	return cc.werr
}

// internal error values; they don't escape to callers
var (
	// abort request body write; don't send cancel
	http2errStopReqBodyWrite = errors.New("http2: aborting request body write")

	// abort request body write, but send stream reset of cancel.
	http2errStopReqBodyWriteAndCancel = errors.New("http2: canceling request")

	http2errReqBodyTooLong = errors.New("http2: request body larger than specified content length")
)

// frameScratchBufferLen returns the length of a buffer to use for
// outgoing request bodies to read/write to/from.
//
// It returns max(1, min(peer's advertised max frame size,
// Request.ContentLength+1, 512KB)).
func (cs *http2clientStream) frameScratchBufferLen(maxFrameSize int) int {
	const max = 512 << 10
	n := int64(maxFrameSize)
	if n > max {
		n = max
	}
	if cl := cs.reqBodyContentLength; cl != -1 && cl+1 < n {
		// Add an extra byte past the declared content-length to
		// give the caller's Request.Body io.Reader a chance to
		// give us more bytes than they declared, so we can catch it
		// early.
		n = cl + 1
	}
	if n < 1 {
		return 1
	}
	return int(n) // doesn't truncate; max is 512K
}

var http2bufPool sync.Pool // of *[]byte

func (cs *http2clientStream) writeRequestBody(req *http.Request) (err error) {
	cc := cs.cc
	body := cs.reqBody
	sentEnd := false // whether we sent the final DATA frame w/ END_STREAM

	hasTrailers := req.Trailer != nil
	remainLen := cs.reqBodyContentLength
	hasContentLen := remainLen != -1

	cc.mu.Lock()
	maxFrameSize := int(cc.maxFrameSize)
	cc.mu.Unlock()

	// Scratch buffer for reading into & writing from.
	scratchLen := cs.frameScratchBufferLen(maxFrameSize)
	var buf []byte
	if bp, ok := http2bufPool.Get().(*[]byte); ok && len(*bp) >= scratchLen {
		defer http2bufPool.Put(bp)
		buf = *bp
	} else {
		buf = make([]byte, scratchLen)
		defer http2bufPool.Put(&buf)
	}

	var sawEOF bool
	for !sawEOF {
		n, err := body.Read(buf)
		if hasContentLen {
			remainLen -= int64(n)
			if remainLen == 0 && err == nil {
				// The request body's Content-Length was predeclared and
				// we just finished reading it all, but the underlying io.Reader
				// returned the final chunk with a nil error (which is one of
				// the two valid things a Reader can do at EOF). Because we'd prefer
				// to send the END_STREAM bit early, double-check that we're actually
				// at EOF. Subsequent reads should return (0, EOF) at this point.
				// If either value is different, we return an error in one of two ways below.
				var scratch [1]byte
				var n1 int
				n1, err = body.Read(scratch[:])
				remainLen -= int64(n1)
			}
			if remainLen < 0 {
				err = http2errReqBodyTooLong
				return err
			}
		}
		if err != nil {
			cc.mu.Lock()
			bodyClosed := cs.reqBodyClosed != nil
			cc.mu.Unlock()
			switch {
			case bodyClosed:
				return http2errStopReqBodyWrite
			case err == io.EOF:
				sawEOF = true
				err = nil
			default:
				return err
			}
		}

		remain := buf[:n]
		for len(remain) > 0 && err == nil {
			var allowed int32
			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)
			if err == nil {
				// TODO(bradfitz): this flush is for latency, not bandwidth.
				// Most requests won't need this. Make this opt-in or
				// opt-out?  Use some heuristic on the body type? Nagel-like
				// timers?  Based on 'n'? Only last chunk of this for loop,
				// unless flow control tokens are low? For now, always.
				// If we change this, see comment below.
				err = cc.bw.Flush()
			}
			cc.wmu.Unlock()
		}
		if err != nil {
			return err
		}
	}

	if sentEnd {
		// Already sent END_STREAM (which implies we have no
		// trailers) and flushed, because currently all
		// WriteData frames above get a flush. So we're done.
		return nil
	}

	// Since the RoundTrip contract permits the caller to "mutate or reuse"
	// a request after the Response's Body is closed, verify that this hasn't
	// happened before accessing the trailers.
	cc.mu.Lock()
	trailer := req.Trailer
	err = cs.abortErr
	cc.mu.Unlock()
	if err != nil {
		return err
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	var trls []byte
	if len(trailer) > 0 {
		trls, err = cc.encodeTrailers(trailer)
		if err != nil {
			return err
		}
	}

	// Two ways to send END_STREAM: either with trailers, or
	// with an empty DATA frame.
	if len(trls) > 0 {
		err = cc.writeHeaders(cs.ID, true, maxFrameSize, trls)
	} else {
		err = cc.fr.WriteData(cs.ID, true, nil)
	}
	if ferr := cc.bw.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return err
}

// awaitFlowControl waits for [1, min(maxBytes, cc.cs.maxFrameSize)] flow
// control tokens from the server.
// It returns either the non-zero number of tokens taken or an error
// if the stream is dead.
func (cs *http2clientStream) awaitFlowControl(maxBytes int) (taken int32, err error) {
	cc := cs.cc
	ctx := cs.ctx
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for {
		if cc.closed {
			return 0, http2errClientConnClosed
		}
		if cs.reqBodyClosed != nil {
			return 0, http2errStopReqBodyWrite
		}
		select {
		case <-cs.abort:
			return 0, cs.abortErr
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-cs.reqCancel:
			return 0, http2errRequestCanceled
		default:
		}
		if a := cs.flow.available(); a > 0 {
			take := a
			if int(take) > maxBytes {

				take = int32(maxBytes) // can't truncate int; take is int32
			}
			if take > int32(cc.maxFrameSize) {
				take = int32(cc.maxFrameSize)
			}
			cs.flow.take(take)
			return take, nil
		}
		cc.cond.Wait()
	}
}

var http2errNilRequestURL = errors.New("http2: Request.URI is nil")

// requires cc.wmu be held.
func (cc *http2ClientConn) encodeHeaders(req *http.Request, addGzipHeader bool, trailers string, contentLength int64) ([]byte, error) {
	cc.hbuf.Reset()
	if req.URL == nil {
		return nil, http2errNilRequestURL
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}
	if !httpguts.ValidHostHeader(host) {
		return nil, errors.New("http2: invalid Host header")
	}

	var path string
	if req.Method != "CONNECT" {
		path = req.URL.RequestURI()
		if !http2validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !http2validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return nil, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid HTTP header name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error, because it may be sensitive.
				return nil, fmt.Errorf("invalid HTTP header value for header %q", k)
			}
		}
	}

	enumerateHeaders := func(f func(name, value string)) {
		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production, see Sections 3.3 and 3.4 of
		// [RFC3986]).
		f(":authority", host)
		m := req.Method
		if m == "" {
			m = http.MethodGet
		}
		f(":method", m)
		if req.Method != "CONNECT" {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		if trailers != "" {
			f("trailer", trailers)
		}

		var didUA bool
		for k, vv := range req.Header {
			if http2asciiEqualFold(k, "host") || http2asciiEqualFold(k, "content-length") {
				// Host is :authority, already sent.
				// Content-Length is automatic, set below.
				continue
			} else if http2asciiEqualFold(k, "connection") ||
				http2asciiEqualFold(k, "proxy-connection") ||
				http2asciiEqualFold(k, "transfer-encoding") ||
				http2asciiEqualFold(k, "upgrade") ||
				http2asciiEqualFold(k, "keep-alive") {
				// Per 8.1.2.2 Connection-Specific Header
				// Fields, don't send connection-specific
				// fields. We have already checked if any
				// are error-worthy so just ignore the rest.
				continue
			} else if http2asciiEqualFold(k, "user-agent") {
				// Match Go's http1 behavior: at most one
				// User-Agent. If set to nil or empty string,
				// then omit it. Otherwise if not mentioned,
				// include the default (below).
				didUA = true
				if len(vv) < 1 {
					continue
				}
				vv = vv[:1]
				if vv[0] == "" {
					continue
				}
			} else if http2asciiEqualFold(k, "cookie") {
				// Per 8.1.2.5 To allow for better compression efficiency, the
				// Cookie header field MAY be split into separate header fields,
				// each with one or more cookie-pairs.
				for _, v := range vv {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++
						// strip space after semicolon if any.
						for p+1 <= len(v) && v[p] == ' ' {
							p++
						}
						v = v[p:]
					}
					if len(v) > 0 {
						f("cookie", v)
					}
				}
				continue
			}

			for _, v := range vv {
				f(k, v)
			}
		}
		if http2shouldSendReqContentLength(req.Method, contentLength) {
			f("content-length", strconv.FormatInt(contentLength, 10))
		}
		if addGzipHeader {
			f("accept-encoding", "gzip")
		}
		if !didUA {
			f("user-agent", http2defaultUserAgent)
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	if hlSize > cc.peerMaxHeaderListSize {
		return nil, http2errRequestHeaderListSize
	}

	trace := httptrace.ContextClientTrace(req.Context())
	traceHeaders := http2traceHasWroteHeaderField(trace)

	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		name, ascii := http2lowerHeader(name)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			return
		}
		cc.writeHeader(name, value)
		if traceHeaders {
			http2traceWroteHeaderField(trace, name, value)
		}
	})

	return cc.hbuf.Bytes(), nil
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func http2shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// requires cc.wmu be held.
func (cc *http2ClientConn) encodeTrailers(trailer http.Header) ([]byte, error) {
	cc.hbuf.Reset()

	hlSize := uint64(0)
	for k, vv := range trailer {
		for _, v := range vv {
			hf := hpack.HeaderField{Name: k, Value: v}
			hlSize += uint64(hf.Size())
		}
	}
	if hlSize > cc.peerMaxHeaderListSize {
		return nil, http2errRequestHeaderListSize
	}

	for k, vv := range trailer {
		lowKey, ascii := http2lowerHeader(k)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			continue
		}
		// Transfer-Encoding, etc.. have already been filtered at the
		// start of RoundTrip
		for _, v := range vv {
			cc.writeHeader(lowKey, v)
		}
	}
	return cc.hbuf.Bytes(), nil
}

func (cc *http2ClientConn) writeHeader(name, value string) {
	if http2VerboseLogs {
		log.Printf("http2: Transport encoding header %q = %q", name, value)
	}
	cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

type http2resAndError struct {
	_   http2incomparable
	res *http.Response
	err error
}

// requires cc.mu be held.
func (cc *http2ClientConn) addStreamLocked(cs *http2clientStream) {
	cs.flow.add(int32(cc.initialWindowSize))
	cs.flow.setConnFlow(&cc.flow)
	cs.inflow.init(http2transportDefaultStreamFlow)
	cs.ID = cc.nextStreamID
	cc.nextStreamID += 2
	cc.streams[cs.ID] = cs
	if cs.ID == 0 {
		panic("assigned stream ID 0")
	}
}

func (cc *http2ClientConn) forgetStreamID(id uint32) {
	cc.mu.Lock()
	slen := len(cc.streams)
	delete(cc.streams, id)
	if len(cc.streams) != slen-1 {
		panic("forgetting unknown stream id")
	}
	cc.lastActive = time.Now()
	if len(cc.streams) == 0 && cc.idleTimer != nil {
		cc.idleTimer.Reset(cc.idleTimeout)
		cc.lastIdle = time.Now()
	}
	// Wake up writeRequestBody via clientStream.awaitFlowControl and
	// wake up RoundTrip if there is a pending request.
	cc.cond.Broadcast()

	closeOnIdle := cc.singleUse || cc.doNotReuse || cc.t.disableKeepAlives() || cc.goAway != nil
	if closeOnIdle && cc.streamsReserved == 0 && len(cc.streams) == 0 {
		if http2VerboseLogs {
			cc.vlogf("http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)", cc, cc.singleUse, cc.nextStreamID-2)
		}
		cc.closed = true
		defer cc.closeConn()
	}

	cc.mu.Unlock()
}

// clientConnReadLoop is the state owned by the clientConn's frame-reading readLoop.
type http2clientConnReadLoop struct {
	_  http2incomparable
	cc *http2ClientConn
}

// readLoop runs in its own goroutine and reads and dispatches frames.
func (cc *http2ClientConn) readLoop() {
	rl := &http2clientConnReadLoop{cc: cc}
	defer rl.cleanup()
	cc.readerErr = rl.run()
	if ce, ok := cc.readerErr.(http2ConnectionError); ok {
		cc.wmu.Lock()
		cc.fr.WriteGoAway(0, http2ErrCode(ce), nil)
		cc.wmu.Unlock()
	}
}

// GoAwayError is returned by the Transport when the server closes the
// TCP connection after sending a GOAWAY frame.
type http2GoAwayError struct {
	LastStreamID uint32
	ErrCode      http2ErrCode
	DebugData    string
}

func (e http2GoAwayError) Error() string {
	return fmt.Sprintf("http2: server sent GOAWAY and closed the connection; LastStreamID=%v, ErrCode=%v, debug=%q",
		e.LastStreamID, e.ErrCode, e.DebugData)
}

func http2isEOFOrNetReadError(err error) bool {
	if err == io.EOF {
		return true
	}
	ne, ok := err.(*net.OpError)
	return ok && ne.Op == "read"
}

func (rl *http2clientConnReadLoop) cleanup() {
	cc := rl.cc
	cc.t.connPool().MarkDead(cc)
	defer cc.closeConn()
	defer close(cc.readerDone)

	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
	}

	// Close any response bodies if the server closes prematurely.
	// TODO: also do this if we've written the headers but not
	// gotten a response yet.
	err := cc.readerErr
	cc.mu.Lock()
	if cc.goAway != nil && http2isEOFOrNetReadError(err) {
		err = http2GoAwayError{
			LastStreamID: cc.goAway.LastStreamID,
			ErrCode:      cc.goAway.ErrCode,
			DebugData:    cc.goAwayDebug,
		}
	} else if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	cc.closed = true

	for _, cs := range cc.streams {
		select {
		case <-cs.peerClosed:
			// The server closed the stream before closing the conn,
			// so no need to interrupt it.
		default:
			cs.abortStreamLocked(err)
		}
	}
	cc.cond.Broadcast()
	cc.mu.Unlock()
}

// countReadFrameError calls Transport.CountError with a string
// representing err.
func (cc *http2ClientConn) countReadFrameError(err error) {
	f := cc.t.CountError
	if f == nil || err == nil {
		return
	}
	if ce, ok := err.(http2ConnectionError); ok {
		errCode := http2ErrCode(ce)
		f(fmt.Sprintf("read_frame_conn_error_%s", errCode.stringToken()))
		return
	}
	if errors.Is(err, io.EOF) {
		f("read_frame_eof")
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		f("read_frame_unexpected_eof")
		return
	}
	if errors.Is(err, http2ErrFrameTooLarge) {
		f("read_frame_too_large")
		return
	}
	f("read_frame_other")
}

func (rl *http2clientConnReadLoop) run() error {
	cc := rl.cc
	gotSettings := false
	readIdleTimeout := cc.t.ReadIdleTimeout
	var t *time.Timer
	if readIdleTimeout != 0 {
		t = time.AfterFunc(readIdleTimeout, cc.healthCheck)
		defer t.Stop()
	}
	for {
		f, err := cc.fr.ReadFrame()
		if t != nil {
			t.Reset(readIdleTimeout)
		}
		if err != nil {
			cc.vlogf("http2: Transport readFrame error on conn %p: (%T) %v", cc, err, err)
		}
		if se, ok := err.(http2StreamError); ok {
			if cs := rl.streamByID(se.StreamID); cs != nil {
				if se.Cause == nil {
					se.Cause = cc.fr.errDetail
				}
				rl.endStreamError(cs, se)
			}
			continue
		} else if err != nil {
			cc.countReadFrameError(err)
			return err
		}
		if http2VerboseLogs {
			cc.vlogf("http2: Transport received %s", http2summarizeFrame(f))
		}
		if !gotSettings {
			if _, ok := f.(*http2SettingsFrame); !ok {
				cc.logf("protocol error: received %T before a SETTINGS frame", f)
				return http2ConnectionError(http2ErrCodeProtocol)
			}
			gotSettings = true
		}

		switch f := f.(type) {
		case *http2MetaHeadersFrame:
			err = rl.processHeaders(f)
		case *http2DataFrame:
			err = rl.processData(f)
		case *http2GoAwayFrame:
			err = rl.processGoAway(f)
		case *http2RSTStreamFrame:
			err = rl.processResetStream(f)
		case *http2SettingsFrame:
			err = rl.processSettings(f)
		case *http2PushPromiseFrame:
			err = rl.processPushPromise(f)
		case *http2WindowUpdateFrame:
			err = rl.processWindowUpdate(f)
		case *http2PingFrame:
			err = rl.processPing(f)
		default:
			cc.logf("Transport: unhandled response frame type %T", f)
		}
		if err != nil {
			if http2VerboseLogs {
				cc.vlogf("http2: Transport conn %p received error from processing frame %v: %v", cc, http2summarizeFrame(f), err)
			}
			return err
		}
	}
}

func (rl *http2clientConnReadLoop) processHeaders(f *http2MetaHeadersFrame) error {
	cs := rl.streamByID(f.StreamID)
	if cs == nil {
		// We'd get here if we canceled a request while the
		// server had its response still in flight. So if this
		// was just something we canceled, ignore it.
		return nil
	}
	if cs.readClosed {
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
			Cause:    errors.New("protocol error: headers after END_STREAM"),
		})
		return nil
	}
	if !cs.firstByte {
		if cs.trace != nil {
			// TODO(bradfitz): move first response byte earlier,
			// when we first read the 9 byte header, not waiting
			// until all the HEADERS+CONTINUATION frames have been
			// merged. This works for now.
			http2traceFirstResponseByte(cs.trace)
		}
		cs.firstByte = true
	}
	if !cs.pastHeaders {
		cs.pastHeaders = true
	} else {
		return rl.processTrailers(cs, f)
	}

	res, err := rl.handleResponse(cs, f)
	if err != nil {
		if _, ok := err.(http2ConnectionError); ok {
			return err
		}
		// Any other error type is a stream error.
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
			Cause:    err,
		})
		return nil // return nil from process* funcs to keep conn alive
	}
	if res == nil {
		// (nil, nil) special case. See handleResponse docs.
		return nil
	}
	cs.resTrailer = &res.Trailer
	cs.res = res
	close(cs.respHeaderRecv)
	if f.StreamEnded() {
		rl.endStream(cs)
	}
	return nil
}

// may return error types nil, or ConnectionError. Any other error value
// is a StreamError of type ErrCodeProtocol. The returned error in that case
// is the detail.
//
// As a special case, handleResponse may return (nil, nil) to skip the
// frame (currently only used for 1xx responses).
func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *http2MetaHeadersFrame) (*http.Response, error) {
	if f.Truncated {
		return nil, http2errResponseHeaderListSize
	}

	status := f.PseudoValue("status")
	if status == "" {
		return nil, errors.New("malformed response from server: missing status pseudo header")
	}
	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, errors.New("malformed response from server: malformed non-numeric status pseudo header")
	}

	regularFields := f.RegularFields()
	strs := make([]string, len(regularFields))
	header := make(http.Header, len(regularFields))
	res := &http.Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		StatusCode: statusCode,
		Status:     status + " " + http.StatusText(statusCode),
	}
	for _, hf := range regularFields {
		key := http2canonicalHeader(hf.Name)
		if key == "Trailer" {
			t := res.Trailer
			if t == nil {
				t = make(http.Header)
				res.Trailer = t
			}
			http2foreachHeaderElement(hf.Value, func(v string) {
				t[http2canonicalHeader(v)] = nil
			})
		} else {
			vv := header[key]
			if vv == nil && len(strs) > 0 {
				// More than likely this will be a single-element key.
				// Most headers aren't multi-valued.
				// Set the capacity on strs[0] to 1, so any future append
				// won't extend the slice into the other strings.
				vv, strs = strs[:1:1], strs[1:]
				vv[0] = hf.Value
				header[key] = vv
			} else {
				header[key] = append(vv, hf.Value)
			}
		}
	}

	if statusCode >= 100 && statusCode <= 199 {
		if f.StreamEnded() {
			return nil, errors.New("1xx informational response with END_STREAM flag")
		}
		cs.num1xx++
		const max1xxResponses = 5 // arbitrary bound on number of informational responses, same as net/http
		if cs.num1xx > max1xxResponses {
			return nil, errors.New("http2: too many 1xx informational responses")
		}
		if fn := cs.get1xxTraceFunc(); fn != nil {
			if err := fn(statusCode, textproto.MIMEHeader(header)); err != nil {
				return nil, err
			}
		}
		if statusCode == 100 {
			http2traceGot100Continue(cs.trace)
			select {
			case cs.on100 <- struct{}{}:
			default:
			}
		}
		cs.pastHeaders = false // do it all again
		return nil, nil
	}

	res.ContentLength = -1
	if clens := res.Header["Content-Length"]; len(clens) == 1 {
		if cl, err := strconv.ParseUint(clens[0], 10, 63); err == nil {
			res.ContentLength = int64(cl)
		} else {
			// TODO: care? unlike http/1, it won't mess up our framing, so it's
			// more safe smuggling-wise to ignore.
		}
	} else if len(clens) > 1 {
		// TODO: care? unlike http/1, it won't mess up our framing, so it's
		// more safe smuggling-wise to ignore.
	} else if f.StreamEnded() && !cs.isHead {
		res.ContentLength = 0
	}

	if cs.isHead {
		res.Body = http2noBody
		return res, nil
	}

	if f.StreamEnded() {
		if res.ContentLength > 0 {
			res.Body = http2missingBody{}
		} else {
			res.Body = http2noBody
		}
		return res, nil
	}

	cs.bufPipe.setBuffer(&http2dataBuffer{expected: res.ContentLength})
	cs.bytesRemain = res.ContentLength
	res.Body = http2transportResponseBody{cs}

	if cs.requestedGzip && http2asciiEqualFold(res.Header.Get("Content-Encoding"), "gzip") {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = &http2gzipReader{body: res.Body}
		res.Uncompressed = true
	}
	return res, nil
}

func (rl *http2clientConnReadLoop) processTrailers(cs *http2clientStream, f *http2MetaHeadersFrame) error {
	if cs.pastTrailers {
		// Too many HEADERS frames for this stream.
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	cs.pastTrailers = true
	if !f.StreamEnded() {
		// We expect that any headers for trailers also
		// has END_STREAM.
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(f.PseudoFields()) > 0 {
		// No pseudo header fields are defined for trailers.
		// TODO: ConnectionError might be overly harsh? Check.
		return http2ConnectionError(http2ErrCodeProtocol)
	}

	trailer := make(http.Header)
	for _, hf := range f.RegularFields() {
		key := http2canonicalHeader(hf.Name)
		trailer[key] = append(trailer[key], hf.Value)
	}
	cs.trailer = trailer

	rl.endStream(cs)
	return nil
}

// transportResponseBody is the concrete type of Transport.RoundTrip's
// Response.Body. It is an io.ReadCloser.
type http2transportResponseBody struct {
	cs *http2clientStream
}

func (b http2transportResponseBody) Read(p []byte) (n int, err error) {
	cs := b.cs
	cc := cs.cc

	if cs.readErr != nil {
		return 0, cs.readErr
	}
	n, err = b.cs.bufPipe.Read(p)
	if cs.bytesRemain != -1 {
		if int64(n) > cs.bytesRemain {
			n = int(cs.bytesRemain)
			if err == nil {
				err = errors.New("net/http: server replied with more than declared Content-Length; truncated")
				cs.abortStream(err)
			}
			cs.readErr = err
			return int(cs.bytesRemain), err
		}
		cs.bytesRemain -= int64(n)
		if err == io.EOF && cs.bytesRemain > 0 {
			err = io.ErrUnexpectedEOF
			cs.readErr = err
			return n, err
		}
	}
	if n == 0 {
		// No flow control tokens to send back.
		return
	}

	cc.mu.Lock()
	connAdd := cc.inflow.add(n)
	var streamAdd int32
	if err == nil { // No need to refresh if the stream is over or failed.
		streamAdd = cs.inflow.add(n)
	}
	cc.mu.Unlock()

	if connAdd != 0 || streamAdd != 0 {
		cc.wmu.Lock()
		defer cc.wmu.Unlock()
		if connAdd != 0 {
			cc.fr.WriteWindowUpdate(0, http2mustUint31(connAdd))
		}
		if streamAdd != 0 {
			cc.fr.WriteWindowUpdate(cs.ID, http2mustUint31(streamAdd))
		}
		cc.bw.Flush()
	}
	return
}

var http2errClosedResponseBody = errors.New("http2: response body closed")

func (b http2transportResponseBody) Close() error {
	cs := b.cs
	cc := cs.cc

	cs.bufPipe.BreakWithError(http2errClosedResponseBody)
	cs.abortStream(http2errClosedResponseBody)

	unread := cs.bufPipe.Len()
	if unread > 0 {
		cc.mu.Lock()
		// Return connection-level flow control.
		connAdd := cc.inflow.add(unread)
		cc.mu.Unlock()

		// TODO(dneil): Acquiring this mutex can block indefinitely.
		// Move flow control return to a goroutine?
		cc.wmu.Lock()
		// Return connection-level flow control.
		if connAdd > 0 {
			cc.fr.WriteWindowUpdate(0, uint32(connAdd))
		}
		cc.bw.Flush()
		cc.wmu.Unlock()
	}

	select {
	case <-cs.donec:
	case <-cs.ctx.Done():
		// See golang/go#49366: The net/http package can cancel the
		// request context after the response body is fully read.
		// Don't treat this as an error.
		return nil
	case <-cs.reqCancel:
		return http2errRequestCanceled
	}
	return nil
}

func (rl *http2clientConnReadLoop) processData(f *http2DataFrame) error {
	cc := rl.cc
	cs := rl.streamByID(f.StreamID)
	data := f.Data()
	if cs == nil {
		cc.mu.Lock()
		neverSent := cc.nextStreamID
		cc.mu.Unlock()
		if f.StreamID >= neverSent {
			// We never asked for this.
			cc.logf("http2: Transport received unsolicited DATA frame; closing connection")
			return http2ConnectionError(http2ErrCodeProtocol)
		}
		// We probably did ask for this, but canceled. Just ignore it.
		// TODO: be stricter here? only silently ignore things which
		// we canceled, but not things which were closed normally
		// by the peer? Tough without accumulating too much state.

		// But at least return their flow control:
		if f.Length > 0 {
			cc.mu.Lock()
			ok := cc.inflow.take(f.Length)
			connAdd := cc.inflow.add(int(f.Length))
			cc.mu.Unlock()
			if !ok {
				return http2ConnectionError(http2ErrCodeFlowControl)
			}
			if connAdd > 0 {
				cc.wmu.Lock()
				cc.fr.WriteWindowUpdate(0, uint32(connAdd))
				cc.bw.Flush()
				cc.wmu.Unlock()
			}
		}
		return nil
	}
	if cs.readClosed {
		cc.logf("protocol error: received DATA after END_STREAM")
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
		})
		return nil
	}
	if !cs.pastHeaders {
		cc.logf("protocol error: received DATA before a HEADERS frame")
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
		})
		return nil
	}
	if f.Length > 0 {
		if cs.isHead && len(data) > 0 {
			cc.logf("protocol error: received DATA on a HEAD request")
			rl.endStreamError(cs, http2StreamError{
				StreamID: f.StreamID,
				Code:     http2ErrCodeProtocol,
			})
			return nil
		}
		// Check connection-level flow control.
		cc.mu.Lock()
		if !http2takeInflows(&cc.inflow, &cs.inflow, f.Length) {
			cc.mu.Unlock()
			return http2ConnectionError(http2ErrCodeFlowControl)
		}
		// Return any padded flow control now, since we won't
		// refund it later on body reads.
		var refund int
		if pad := int(f.Length) - len(data); pad > 0 {
			refund += pad
		}

		didReset := false
		var err error
		if len(data) > 0 {
			if _, err = cs.bufPipe.Write(data); err != nil {
				// Return len(data) now if the stream is already closed,
				// since data will never be read.
				didReset = true
				refund += len(data)
			}
		}

		sendConn := cc.inflow.add(refund)
		var sendStream int32
		if !didReset {
			sendStream = cs.inflow.add(refund)
		}
		cc.mu.Unlock()

		if sendConn > 0 || sendStream > 0 {
			cc.wmu.Lock()
			if sendConn > 0 {
				cc.fr.WriteWindowUpdate(0, uint32(sendConn))
			}
			if sendStream > 0 {
				cc.fr.WriteWindowUpdate(cs.ID, uint32(sendStream))
			}
			cc.bw.Flush()
			cc.wmu.Unlock()
		}

		if err != nil {
			rl.endStreamError(cs, err)
			return nil
		}
	}

	if f.StreamEnded() {
		rl.endStream(cs)
	}
	return nil
}

func (rl *http2clientConnReadLoop) endStream(cs *http2clientStream) {
	// TODO: check that any declared content-length matches, like
	// server.go's (*stream).endStream method.
	if !cs.readClosed {
		cs.readClosed = true
		// Close cs.bufPipe and cs.peerClosed with cc.mu held to avoid a
		// race condition: The caller can read io.EOF from Response.Body
		// and close the body before we close cs.peerClosed, causing
		// cleanupWriteRequest to send a RST_STREAM.
		rl.cc.mu.Lock()
		defer rl.cc.mu.Unlock()
		cs.bufPipe.closeWithErrorAndCode(io.EOF, cs.copyTrailers)
		close(cs.peerClosed)
	}
}

func (rl *http2clientConnReadLoop) endStreamError(cs *http2clientStream, err error) {
	cs.readAborted = true
	cs.abortStream(err)
}

func (rl *http2clientConnReadLoop) streamByID(id uint32) *http2clientStream {
	rl.cc.mu.Lock()
	defer rl.cc.mu.Unlock()
	cs := rl.cc.streams[id]
	if cs != nil && !cs.readAborted {
		return cs
	}
	return nil
}

func (cs *http2clientStream) copyTrailers() {
	for k, vv := range cs.trailer {
		t := cs.resTrailer
		if *t == nil {
			*t = make(http.Header)
		}
		(*t)[k] = vv
	}
}

func (rl *http2clientConnReadLoop) processGoAway(f *http2GoAwayFrame) error {
	cc := rl.cc
	cc.t.connPool().MarkDead(cc)
	if f.ErrCode != 0 {
		// TODO: deal with GOAWAY more. particularly the error code
		cc.vlogf("transport got GOAWAY with error code = %v", f.ErrCode)
		if fn := cc.t.CountError; fn != nil {
			fn("recv_goaway_" + f.ErrCode.stringToken())
		}
	}
	cc.setGoAway(f)
	return nil
}

func (rl *http2clientConnReadLoop) processSettings(f *http2SettingsFrame) error {
	cc := rl.cc
	// Locking both mu and wmu here allows frame encoding to read settings with only wmu held.
	// Acquiring wmu when f.IsAck() is unnecessary, but convenient and mostly harmless.
	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	if err := rl.processSettingsNoWrite(f); err != nil {
		return err
	}
	if !f.IsAck() {
		cc.fr.WriteSettingsAck()
		cc.bw.Flush()
	}
	return nil
}

func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *http2SettingsFrame) error {
	cc := rl.cc
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if f.IsAck() {
		if cc.wantSettingsAck {
			cc.wantSettingsAck = false
			return nil
		}
		return http2ConnectionError(http2ErrCodeProtocol)
	}

	var seenMaxConcurrentStreams bool
	err := f.ForeachSetting(func(s http2Setting) error {
		switch s.ID {
		case http2SettingMaxFrameSize:
			cc.maxFrameSize = s.Val
		case http2SettingMaxConcurrentStreams:
			cc.maxConcurrentStreams = s.Val
			seenMaxConcurrentStreams = true
		case http2SettingMaxHeaderListSize:
			cc.peerMaxHeaderListSize = uint64(s.Val)
		case http2SettingInitialWindowSize:
			// Values above the maximum flow-control
			// window size of 2^31-1 MUST be treated as a
			// connection error (Section 5.4.1) of type
			// FLOW_CONTROL_ERROR.
			if s.Val > math.MaxInt32 {
				return http2ConnectionError(http2ErrCodeFlowControl)
			}

			// Adjust flow control of currently-open
			// frames by the difference of the old initial
			// window size and this one.
			delta := int32(s.Val) - int32(cc.initialWindowSize)
			for _, cs := range cc.streams {
				cs.flow.add(delta)
			}
			cc.cond.Broadcast()

			cc.initialWindowSize = s.Val
		case http2SettingHeaderTableSize:
			cc.henc.SetMaxDynamicTableSize(s.Val)
			cc.peerMaxHeaderTableSize = s.Val
		default:
			cc.vlogf("Unhandled Setting: %v", s)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if !cc.seenSettings {
		if !seenMaxConcurrentStreams {
			// This was the servers initial SETTINGS frame and it
			// didn't contain a MAX_CONCURRENT_STREAMS field so
			// increase the number of concurrent streams this
			// connection can establish to our default.
			cc.maxConcurrentStreams = http2defaultMaxConcurrentStreams
		}
		cc.seenSettings = true
	}

	return nil
}

func (rl *http2clientConnReadLoop) processWindowUpdate(f *http2WindowUpdateFrame) error {
	cc := rl.cc
	cs := rl.streamByID(f.StreamID)
	if f.StreamID != 0 && cs == nil {
		return nil
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	fl := &cc.flow
	if cs != nil {
		fl = &cs.flow
	}
	if !fl.add(int32(f.Increment)) {
		return http2ConnectionError(http2ErrCodeFlowControl)
	}
	cc.cond.Broadcast()
	return nil
}

func (rl *http2clientConnReadLoop) processResetStream(f *http2RSTStreamFrame) error {
	cs := rl.streamByID(f.StreamID)
	if cs == nil {
		// TODO: return error if server tries to RST_STREAM an idle stream
		return nil
	}
	serr := http2streamError(cs.ID, f.ErrCode)
	serr.Cause = http2errFromPeer
	if f.ErrCode == http2ErrCodeProtocol {
		rl.cc.SetDoNotReuse()
	}
	if fn := cs.cc.t.CountError; fn != nil {
		fn("recv_rststream_" + f.ErrCode.stringToken())
	}
	cs.abortStream(serr)

	cs.bufPipe.CloseWithError(serr)
	return nil
}

// Ping sends a PING frame to the server and waits for the ack.
func (cc *http2ClientConn) Ping(ctx context.Context) error {
	c := make(chan struct{})
	// Generate a random payload
	var p [8]byte
	for {
		if _, err := rand.Read(p[:]); err != nil {
			return err
		}
		cc.mu.Lock()
		// check for dup before insert
		if _, found := cc.pings[p]; !found {
			cc.pings[p] = c
			cc.mu.Unlock()
			break
		}
		cc.mu.Unlock()
	}
	errc := make(chan error, 1)
	go func() {
		cc.wmu.Lock()
		defer cc.wmu.Unlock()
		if err := cc.fr.WritePing(false, p); err != nil {
			errc <- err
			return
		}
		if err := cc.bw.Flush(); err != nil {
			errc <- err
			return
		}
	}()
	select {
	case <-c:
		return nil
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-cc.readerDone:
		// connection closed
		return cc.readerErr
	}
}

func (rl *http2clientConnReadLoop) processPing(f *http2PingFrame) error {
	if f.IsAck() {
		cc := rl.cc
		cc.mu.Lock()
		defer cc.mu.Unlock()
		// If ack, notify listener if any
		if c, ok := cc.pings[f.Data]; ok {
			close(c)
			delete(cc.pings, f.Data)
		}
		return nil
	}
	cc := rl.cc
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	if err := cc.fr.WritePing(true, f.Data); err != nil {
		return err
	}
	return cc.bw.Flush()
}

func (rl *http2clientConnReadLoop) processPushPromise(f *http2PushPromiseFrame) error {
	// We told the peer we don't want them.
	// Spec says:
	// "PUSH_PROMISE MUST NOT be sent if the SETTINGS_ENABLE_PUSH
	// setting of the peer endpoint is set to 0. An endpoint that
	// has set this setting and has received acknowledgement MUST
	// treat the receipt of a PUSH_PROMISE frame as a connection
	// error (Section 5.4.1) of type PROTOCOL_ERROR."
	return http2ConnectionError(http2ErrCodeProtocol)
}

func (cc *http2ClientConn) writeStreamReset(streamID uint32, code http2ErrCode, err error) {
	// TODO: map err to more interesting error codes, once the
	// HTTP community comes up with some. But currently for
	// RST_STREAM there's no equivalent to GOAWAY frame's debug
	// data, and the error codes are all pretty vague ("cancel").
	cc.wmu.Lock()
	cc.fr.WriteRSTStream(streamID, code)
	cc.bw.Flush()
	cc.wmu.Unlock()
}

var (
	http2errResponseHeaderListSize = errors.New("http2: response header list larger than advertised limit")
	http2errRequestHeaderListSize  = errors.New("http2: request header list larger than peer's advertised limit")
)

func (cc *http2ClientConn) logf(format string, args ...interface{}) {
	cc.t.logf(format, args...)
}

func (cc *http2ClientConn) vlogf(format string, args ...interface{}) {
	cc.t.vlogf(format, args...)
}

func (t *http2Transport) vlogf(format string, args ...interface{}) {
	if http2VerboseLogs {
		t.logf(format, args...)
	}
}

func (t *http2Transport) logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

var http2noBody io.ReadCloser = http2noBodyReader{}

type http2noBodyReader struct{}

func (http2noBodyReader) Close() error { return nil }

func (http2noBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

type http2missingBody struct{}

func (http2missingBody) Close() error { return nil }

func (http2missingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func http2strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

type http2erringRoundTripper struct{ err error }

func (rt http2erringRoundTripper) RoundTripErr() error { return rt.err }

func (rt http2erringRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type http2gzipReader struct {
	_    http2incomparable
	body io.ReadCloser // underlying Response.Body
	zr   *gzip.Reader  // lazily-initialized gzip reader
	zerr error         // sticky error
}

func (gz *http2gzipReader) Read(p []byte) (n int, err error) {
	if gz.zerr != nil {
		return 0, gz.zerr
	}
	if gz.zr == nil {
		gz.zr, err = gzip.NewReader(gz.body)
		if err != nil {
			gz.zerr = err
			return 0, err
		}
	}
	return gz.zr.Read(p)
}

func (gz *http2gzipReader) Close() error {
	if err := gz.body.Close(); err != nil {
		return err
	}
	gz.zerr = fs.ErrClosed
	return nil
}

type http2errorReader struct{ err error }

func (r http2errorReader) Read(p []byte) (int, error) { return 0, r.err }

// isConnectionCloseRequest reports whether req should use its own
// connection for a single request and then close the connection.
func http2isConnectionCloseRequest(req *http.Request) bool {
	return req.Close || httpguts.HeaderValuesContainsToken(req.Header["Connection"], "close")
}

// registerHTTPSProtocol calls Transport.RegisterProtocol but
// converting panics into errors.
func http2registerHTTPSProtocol(t *http.Transport, rt http2noDialH2RoundTripper) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	t.RegisterProtocol("https", rt)
	return nil
}

// noDialH2RoundTripper is a RoundTripper which only tries to complete the request
// if there's already has a cached connection to the host.
// (The field is exported so it can be accessed via reflect from net/http; tested
// by TestNoDialH2RoundTripperType)
type http2noDialH2RoundTripper struct{ *http2Transport }

func (rt http2noDialH2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rt.http2Transport.RoundTrip(req)
	if http2isNoCachedConnError(err) {
		return nil, http.ErrSkipAltProtocol
	}
	return res, err
}

func (t *http2Transport) idleConnTimeout() time.Duration {
	if t.t1 != nil {
		return t.t1.IdleConnTimeout
	}
	return 0
}

func http2traceGetConn(req *http.Request, hostPort string) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace == nil || trace.GetConn == nil {
		return
	}
	trace.GetConn(hostPort)
}

func http2traceGotConn(req *http.Request, cc *http2ClientConn, reused bool) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace == nil || trace.GotConn == nil {
		return
	}
	ci := httptrace.GotConnInfo{Conn: cc.tconn}
	ci.Reused = reused
	cc.mu.Lock()
	ci.WasIdle = len(cc.streams) == 0 && reused
	if ci.WasIdle && !cc.lastActive.IsZero() {
		ci.IdleTime = time.Since(cc.lastActive)
	}
	cc.mu.Unlock()

	trace.GotConn(ci)
}

func http2traceWroteHeaders(trace *httptrace.ClientTrace) {
	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}
}

func http2traceGot100Continue(trace *httptrace.ClientTrace) {
	if trace != nil && trace.Got100Continue != nil {
		trace.Got100Continue()
	}
}

func http2traceWait100Continue(trace *httptrace.ClientTrace) {
	if trace != nil && trace.Wait100Continue != nil {
		trace.Wait100Continue()
	}
}

func http2traceWroteRequest(trace *httptrace.ClientTrace, err error) {
	if trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
	}
}

func http2traceFirstResponseByte(trace *httptrace.ClientTrace) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		trace.GotFirstResponseByte()
	}
}

// writeFramer is implemented by any type that is used to write frames.
type http2writeFramer interface {
	writeFrame(http2writeContext) error

	// staysWithinBuffer reports whether this writer promises that
	// it will only write less than or equal to size bytes, and it
	// won't Flush the write context.
	staysWithinBuffer(size int) bool
}

// writeContext is the interface needed by the various frame writer
// types below. All the writeFrame methods below are scheduled via the
// frame writing scheduler (see writeScheduler in writesched.go).
//
// This interface is implemented by *serverConn.
//
// TODO: decide whether to a) use this in the client code (which didn't
// end up using this yet, because it has a simpler design, not
// currently implementing priorities), or b) delete this and
// make the server code a bit more concrete.
type http2writeContext interface {
	Framer() *http2Framer
	Flush() error
	CloseConn() error
	// HeaderEncoder returns an HPACK encoder that writes to the
	// returned buffer.
	HeaderEncoder() (*hpack.Encoder, *bytes.Buffer)
}

// writeEndsStream reports whether w writes a frame that will transition
// the stream to a half-closed local state. This returns false for RST_STREAM,
// which closes the entire stream (not just the local half).
func http2writeEndsStream(w http2writeFramer) bool {
	switch v := w.(type) {
	case *http2writeData:
		return v.endStream
	case *http2writeResHeaders:
		return v.endStream
	case nil:
		// This can only happen if the caller reuses w after it's
		// been intentionally nil'ed out to prevent use. Keep this
		// here to catch future refactoring breaking it.
		panic("writeEndsStream called on nil writeFramer")
	}
	return false
}

type http2flushFrameWriter struct{}

func (http2flushFrameWriter) writeFrame(ctx http2writeContext) error {
	return ctx.Flush()
}

func (http2flushFrameWriter) staysWithinBuffer(max int) bool { return false }

type http2writeSettings []http2Setting

func (s http2writeSettings) staysWithinBuffer(max int) bool {
	const settingSize = 6 // uint16 + uint32
	return http2frameHeaderLen+settingSize*len(s) <= max

}

func (s http2writeSettings) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteSettings([]http2Setting(s)...)
}

type http2writeGoAway struct {
	maxStreamID uint32
	code        http2ErrCode
}

func (p *http2writeGoAway) writeFrame(ctx http2writeContext) error {
	err := ctx.Framer().WriteGoAway(p.maxStreamID, p.code, nil)
	ctx.Flush() // ignore error: we're hanging up on them anyway
	return err
}

func (*http2writeGoAway) staysWithinBuffer(max int) bool { return false } // flushes

type http2writeData struct {
	streamID  uint32
	p         []byte
	endStream bool
}

func (w *http2writeData) String() string {
	return fmt.Sprintf("writeData(stream=%d, p=%d, endStream=%v)", w.streamID, len(w.p), w.endStream)
}

func (w *http2writeData) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteData(w.streamID, w.endStream, w.p)
}

func (w *http2writeData) staysWithinBuffer(max int) bool {
	return http2frameHeaderLen+len(w.p) <= max
}

// handlerPanicRST is the message sent from handler goroutines when
// the handler panics.
type http2handlerPanicRST struct {
	StreamID uint32
}

func (hp http2handlerPanicRST) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteRSTStream(hp.StreamID, http2ErrCodeInternal)
}

func (hp http2handlerPanicRST) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

func (se http2StreamError) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteRSTStream(se.StreamID, se.Code)
}

func (se http2StreamError) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

type http2writePingAck struct{ pf *http2PingFrame }

func (w http2writePingAck) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WritePing(true, w.pf.Data)
}

func (w http2writePingAck) staysWithinBuffer(max int) bool {
	return http2frameHeaderLen+len(w.pf.Data) <= max
}

type http2writeSettingsAck struct{}

func (http2writeSettingsAck) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteSettingsAck()
}

func (http2writeSettingsAck) staysWithinBuffer(max int) bool { return http2frameHeaderLen <= max }

// splitHeaderBlock splits headerBlock into fragments so that each fragment fits
// in a single frame, then calls fn for each fragment. firstFrag/lastFrag are true
// for the first/last fragment, respectively.
func http2splitHeaderBlock(ctx http2writeContext, headerBlock []byte, fn func(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error) error {
	// For now we're lazy and just pick the minimum MAX_FRAME_SIZE
	// that all peers must support (16KB). Later we could care
	// more and send larger frames if the peer advertised it, but
	// there's little point. Most headers are small anyway (so we
	// generally won't have CONTINUATION frames), and extra frames
	// only waste 9 bytes anyway.
	const maxFrameSize = 16384

	first := true
	for len(headerBlock) > 0 {
		frag := headerBlock
		if len(frag) > maxFrameSize {
			frag = frag[:maxFrameSize]
		}
		headerBlock = headerBlock[len(frag):]
		if err := fn(ctx, frag, first, len(headerBlock) == 0); err != nil {
			return err
		}
		first = false
	}
	return nil
}

// writeResHeaders is a request to write a HEADERS and 0+ CONTINUATION frames
// for HTTP response headers or trailers from a server handler.
type http2writeResHeaders struct {
	streamID    uint32
	httpResCode int         // 0 means no ":status" line
	h           http.Header // may be nil
	trailers    []string    // if non-nil, which keys of h to write. nil means all.
	endStream   bool

	date          string
	contentType   string
	contentLength string
}

func http2encKV(enc *hpack.Encoder, k, v string) {
	if http2VerboseLogs {
		log.Printf("http2: server encoding header %q = %q", k, v)
	}
	enc.WriteField(hpack.HeaderField{Name: k, Value: v})
}

func (w *http2writeResHeaders) staysWithinBuffer(max int) bool {
	// TODO: this is a common one. It'd be nice to return true
	// here and get into the fast path if we could be clever and
	// calculate the size fast enough, or at least a conservative
	// upper bound that usually fires. (Maybe if w.h and
	// w.trailers are nil, so we don't need to enumerate it.)
	// Otherwise I'm afraid that just calculating the length to
	// answer this question would be slower than the ~2µs benefit.
	return false
}

func (w *http2writeResHeaders) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	if w.httpResCode != 0 {
		http2encKV(enc, ":status", http2httpCodeString(w.httpResCode))
	}

	http2encodeHeaders(enc, w.h, w.trailers)

	if w.contentType != "" {
		http2encKV(enc, "content-type", w.contentType)
	}
	if w.contentLength != "" {
		http2encKV(enc, "content-length", w.contentLength)
	}
	if w.date != "" {
		http2encKV(enc, "date", w.date)
	}

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 && w.trailers == nil {
		panic("unexpected empty hpack")
	}

	return http2splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *http2writeResHeaders) writeHeaderBlock(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WriteHeaders(http2HeadersFrameParam{
			StreamID:      w.streamID,
			BlockFragment: frag,
			EndStream:     w.endStream,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

// writePushPromise is a request to write a PUSH_PROMISE and 0+ CONTINUATION frames.
type http2writePushPromise struct {
	streamID uint32   // pusher stream
	method   string   // for :method
	url      *url.URL // for :scheme, :authority, :path
	h        http.Header

	// Creates an ID for a pushed stream. This runs on serveG just before
	// the frame is written. The returned ID is copied to promisedID.
	allocatePromisedID func() (uint32, error)
	promisedID         uint32
}

func (w *http2writePushPromise) staysWithinBuffer(max int) bool {
	// TODO: see writeResHeaders.staysWithinBuffer
	return false
}

func (w *http2writePushPromise) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	http2encKV(enc, ":method", w.method)
	http2encKV(enc, ":scheme", w.url.Scheme)
	http2encKV(enc, ":authority", w.url.Host)
	http2encKV(enc, ":path", w.url.RequestURI())
	http2encodeHeaders(enc, w.h, nil)

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 {
		panic("unexpected empty hpack")
	}

	return http2splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *http2writePushPromise) writeHeaderBlock(ctx http2writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WritePushPromise(http2PushPromiseParam{
			StreamID:      w.streamID,
			PromiseID:     w.promisedID,
			BlockFragment: frag,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

type http2write100ContinueHeadersFrame struct {
	streamID uint32
}

func (w http2write100ContinueHeadersFrame) writeFrame(ctx http2writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()
	http2encKV(enc, ":status", "100")
	return ctx.Framer().WriteHeaders(http2HeadersFrameParam{
		StreamID:      w.streamID,
		BlockFragment: buf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

func (w http2write100ContinueHeadersFrame) staysWithinBuffer(max int) bool {
	// Sloppy but conservative:
	return 9+2*(len(":status")+len("100")) <= max
}

type http2writeWindowUpdate struct {
	streamID uint32 // or 0 for conn-level
	n        uint32
}

func (wu http2writeWindowUpdate) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

func (wu http2writeWindowUpdate) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteWindowUpdate(wu.streamID, wu.n)
}

// encodeHeaders encodes an http.Header. If keys is not nil, then (k, h[k])
// is encoded only if k is in keys.
func http2encodeHeaders(enc *hpack.Encoder, h http.Header, keys []string) {
	if keys == nil {
		sorter := http2sorterPool.Get().(*http2sorter)
		// Using defer here, since the returned keys from the
		// sorter.Keys method is only valid until the sorter
		// is returned:
		defer http2sorterPool.Put(sorter)
		keys = sorter.Keys(h)
	}
	for _, k := range keys {
		vv := h[k]
		k, ascii := http2lowerHeader(k)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			continue
		}
		if !http2validWireHeaderFieldName(k) {
			// Skip it as backup paranoia. Per
			// golang.org/issue/14048, these should
			// already be rejected at a higher level.
			continue
		}
		isTE := k == "transfer-encoding"
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// TODO: return an error? golang.org/issue/14048
				// For now just omit it.
				continue
			}
			// TODO: more of "8.1.2.2 Connection-Specific Header Fields"
			if isTE && v != "trailers" {
				continue
			}
			http2encKV(enc, k, v)
		}
	}
}

// WriteScheduler is the interface implemented by HTTP/2 write schedulers.
// Methods are never called concurrently.
type http2WriteScheduler interface {
	// OpenStream opens a new stream in the write scheduler.
	// It is illegal to call this with streamID=0 or with a streamID that is
	// already open -- the call may panic.
	OpenStream(streamID uint32, options http2OpenStreamOptions)

	// CloseStream closes a stream in the write scheduler. Any frames queued on
	// this stream should be discarded. It is illegal to call this on a stream
	// that is not open -- the call may panic.
	CloseStream(streamID uint32)

	// AdjustStream adjusts the priority of the given stream. This may be called
	// on a stream that has not yet been opened or has been closed. Note that
	// RFC 7540 allows PRIORITY frames to be sent on streams in any state. See:
	// https://tools.ietf.org/html/rfc7540#section-5.1
	AdjustStream(streamID uint32, priority http2PriorityParam)

	// Push queues a frame in the scheduler. In most cases, this will not be
	// called with wr.StreamID()!=0 unless that stream is currently open. The one
	// exception is RST_STREAM frames, which may be sent on idle or closed streams.
	Push(wr http2FrameWriteRequest)

	// Pop dequeues the next frame to write. Returns false if no frames can
	// be written. Frames with a given wr.StreamID() are Pop'd in the same
	// order they are Push'd, except RST_STREAM frames. No frames should be
	// discarded except by CloseStream.
	Pop() (wr http2FrameWriteRequest, ok bool)
}

// OpenStreamOptions specifies extra options for WriteScheduler.OpenStream.
type http2OpenStreamOptions struct {
	// PusherID is zero if the stream was initiated by the client. Otherwise,
	// PusherID names the stream that pushed the newly opened stream.
	PusherID uint32
}

// FrameWriteRequest is a request to write a frame.
type http2FrameWriteRequest struct {
	// write is the interface value that does the writing, once the
	// WriteScheduler has selected this frame to write. The write
	// functions are all defined in write.go.
	write http2writeFramer

	// stream is the stream on which this frame will be written.
	// nil for non-stream frames like PING and SETTINGS.
	// nil for RST_STREAM streams, which use the StreamError.StreamID field instead.
	stream *http2stream

	// done, if non-nil, must be a buffered channel with space for
	// 1 message and is sent the return value from write (or an
	// earlier error) when the frame has been written.
	done chan error
}

// StreamID returns the id of the stream this frame will be written to.
// 0 is used for non-stream frames such as PING and SETTINGS.
func (wr http2FrameWriteRequest) StreamID() uint32 {
	if wr.stream == nil {
		if se, ok := wr.write.(http2StreamError); ok {
			// (*serverConn).resetStream doesn't set
			// stream because it doesn't necessarily have
			// one. So special case this type of write
			// message.
			return se.StreamID
		}
		return 0
	}
	return wr.stream.id
}

// isControl reports whether wr is a control frame for MaxQueuedControlFrames
// purposes. That includes non-stream frames and RST_STREAM frames.
func (wr http2FrameWriteRequest) isControl() bool {
	return wr.stream == nil
}

// DataSize returns the number of flow control bytes that must be consumed
// to write this entire frame. This is 0 for non-DATA frames.
func (wr http2FrameWriteRequest) DataSize() int {
	if wd, ok := wr.write.(*http2writeData); ok {
		return len(wd.p)
	}
	return 0
}

// Consume consumes min(n, available) bytes from this frame, where available
// is the number of flow control bytes available on the stream. Consume returns
// 0, 1, or 2 frames, where the integer return value gives the number of frames
// returned.
//
// If flow control prevents consuming any bytes, this returns (_, _, 0). If
// the entire frame was consumed, this returns (wr, _, 1). Otherwise, this
// returns (consumed, rest, 2), where 'consumed' contains the consumed bytes and
// 'rest' contains the remaining bytes. The consumed bytes are deducted from the
// underlying stream's flow control budget.
func (wr http2FrameWriteRequest) Consume(n int32) (http2FrameWriteRequest, http2FrameWriteRequest, int) {
	var empty http2FrameWriteRequest

	// Non-DATA frames are always consumed whole.
	wd, ok := wr.write.(*http2writeData)
	if !ok || len(wd.p) == 0 {
		return wr, empty, 1
	}

	// Might need to split after applying limits.
	allowed := wr.stream.flow.available()
	if n < allowed {
		allowed = n
	}
	if wr.stream.sc.maxFrameSize < allowed {
		allowed = wr.stream.sc.maxFrameSize
	}
	if allowed <= 0 {
		return empty, empty, 0
	}
	if len(wd.p) > int(allowed) {
		wr.stream.flow.take(allowed)
		consumed := http2FrameWriteRequest{
			stream: wr.stream,
			write: &http2writeData{
				streamID: wd.streamID,
				p:        wd.p[:allowed],
				// Even if the original had endStream set, there
				// are bytes remaining because len(wd.p) > allowed,
				// so we know endStream is false.
				endStream: false,
			},
			// Our caller is blocking on the final DATA frame, not
			// this intermediate frame, so no need to wait.
			done: nil,
		}
		rest := http2FrameWriteRequest{
			stream: wr.stream,
			write: &http2writeData{
				streamID:  wd.streamID,
				p:         wd.p[allowed:],
				endStream: wd.endStream,
			},
			done: wr.done,
		}
		return consumed, rest, 2
	}

	// The frame is consumed whole.
	// NB: This cast cannot overflow because allowed is <= math.MaxInt32.
	wr.stream.flow.take(int32(len(wd.p)))
	return wr, empty, 1
}

// String is for debugging only.
func (wr http2FrameWriteRequest) String() string {
	var des string
	if s, ok := wr.write.(fmt.Stringer); ok {
		des = s.String()
	} else {
		des = fmt.Sprintf("%T", wr.write)
	}
	return fmt.Sprintf("[FrameWriteRequest stream=%d, ch=%v, writer=%v]", wr.StreamID(), wr.done != nil, des)
}

// replyToWriter sends err to wr.done and panics if the send must block
// This does nothing if wr.done is nil.
func (wr *http2FrameWriteRequest) replyToWriter(err error) {
	if wr.done == nil {
		return
	}
	select {
	case wr.done <- err:
	default:
		panic(fmt.Sprintf("unbuffered done channel passed in for type %T", wr.write))
	}
	wr.write = nil // prevent use (assume it's tainted after wr.done send)
}

// writeQueue is used by implementations of WriteScheduler.
type http2writeQueue struct {
	s          []http2FrameWriteRequest
	prev, next *http2writeQueue
}

func (q *http2writeQueue) empty() bool { return len(q.s) == 0 }

func (q *http2writeQueue) push(wr http2FrameWriteRequest) {
	q.s = append(q.s, wr)
}

func (q *http2writeQueue) shift() http2FrameWriteRequest {
	if len(q.s) == 0 {
		panic("invalid use of queue")
	}
	wr := q.s[0]
	// TODO: less copy-happy queue.
	copy(q.s, q.s[1:])
	q.s[len(q.s)-1] = http2FrameWriteRequest{}
	q.s = q.s[:len(q.s)-1]
	return wr
}

// consume consumes up to n bytes from q.s[0]. If the frame is
// entirely consumed, it is removed from the queue. If the frame
// is partially consumed, the frame is kept with the consumed
// bytes removed. Returns true iff any bytes were consumed.
func (q *http2writeQueue) consume(n int32) (http2FrameWriteRequest, bool) {
	if len(q.s) == 0 {
		return http2FrameWriteRequest{}, false
	}
	consumed, rest, numresult := q.s[0].Consume(n)
	switch numresult {
	case 0:
		return http2FrameWriteRequest{}, false
	case 1:
		q.shift()
	case 2:
		q.s[0] = rest
	}
	return consumed, true
}

type http2writeQueuePool []*http2writeQueue

// put inserts an unused writeQueue into the pool.

// put inserts an unused writeQueue into the pool.
func (p *http2writeQueuePool) put(q *http2writeQueue) {
	for i := range q.s {
		q.s[i] = http2FrameWriteRequest{}
	}
	q.s = q.s[:0]
	*p = append(*p, q)
}

// get returns an empty writeQueue.
func (p *http2writeQueuePool) get() *http2writeQueue {
	ln := len(*p)
	if ln == 0 {
		return new(http2writeQueue)
	}
	x := ln - 1
	q := (*p)[x]
	(*p)[x] = nil
	*p = (*p)[:x]
	return q
}

// RFC 7540, Section 5.3.5: the default weight is 16.
const http2priorityDefaultWeight = 15 // 16 = 15 + 1

// PriorityWriteSchedulerConfig configures a priorityWriteScheduler.
type http2PriorityWriteSchedulerConfig struct {
	// MaxClosedNodesInTree controls the maximum number of closed streams to
	// retain in the priority tree. Setting this to zero saves a small amount
	// of memory at the cost of performance.
	//
	// See RFC 7540, Section 5.3.4:
	//   "It is possible for a stream to become closed while prioritization
	//   information ... is in transit. ... This potentially creates suboptimal
	//   prioritization, since the stream could be given a priority that is
	//   different from what is intended. To avoid these problems, an endpoint
	//   SHOULD retain stream prioritization state for a period after streams
	//   become closed. The longer state is retained, the lower the chance that
	//   streams are assigned incorrect or default priority values."
	MaxClosedNodesInTree int

	// MaxIdleNodesInTree controls the maximum number of idle streams to
	// retain in the priority tree. Setting this to zero saves a small amount
	// of memory at the cost of performance.
	//
	// See RFC 7540, Section 5.3.4:
	//   Similarly, streams that are in the "idle" state can be assigned
	//   priority or become a parent of other streams. This allows for the
	//   creation of a grouping node in the dependency tree, which enables
	//   more flexible expressions of priority. Idle streams begin with a
	//   default priority (Section 5.3.5).
	MaxIdleNodesInTree int

	// ThrottleOutOfOrderWrites enables write throttling to help ensure that
	// data is delivered in priority order. This works around a race where
	// stream B depends on stream A and both streams are about to call Write
	// to queue DATA frames. If B wins the race, a naive scheduler would eagerly
	// write as much data from B as possible, but this is suboptimal because A
	// is a higher-priority stream. With throttling enabled, we write a small
	// amount of data from B to minimize the amount of bandwidth that B can
	// steal from A.
	ThrottleOutOfOrderWrites bool
}

// NewPriorityWriteScheduler constructs a WriteScheduler that schedules
// frames by following HTTP/2 priorities as described in RFC 7540 Section 5.3.
// If cfg is nil, default options are used.
func http2NewPriorityWriteScheduler(cfg *http2PriorityWriteSchedulerConfig) http2WriteScheduler {
	if cfg == nil {
		// For justification of these defaults, see:
		// https://docs.google.com/document/d/1oLhNg1skaWD4_DtaoCxdSRN5erEXrH-KnLrMwEpOtFY
		cfg = &http2PriorityWriteSchedulerConfig{
			MaxClosedNodesInTree:     10,
			MaxIdleNodesInTree:       10,
			ThrottleOutOfOrderWrites: false,
		}
	}

	ws := &http2priorityWriteScheduler{
		nodes:                make(map[uint32]*http2priorityNode),
		maxClosedNodesInTree: cfg.MaxClosedNodesInTree,
		maxIdleNodesInTree:   cfg.MaxIdleNodesInTree,
		enableWriteThrottle:  cfg.ThrottleOutOfOrderWrites,
	}
	ws.nodes[0] = &ws.root
	if cfg.ThrottleOutOfOrderWrites {
		ws.writeThrottleLimit = 1024
	} else {
		ws.writeThrottleLimit = math.MaxInt32
	}
	return ws
}

type http2priorityNodeState int

const (
	http2priorityNodeOpen http2priorityNodeState = iota
	http2priorityNodeClosed
	http2priorityNodeIdle
)

// priorityNode is a node in an HTTP/2 priority tree.
// Each node is associated with a single stream ID.
// See RFC 7540, Section 5.3.
type http2priorityNode struct {
	q            http2writeQueue        // queue of pending frames to write
	id           uint32                 // id of the stream, or 0 for the root of the tree
	weight       uint8                  // the actual weight is weight+1, so the value is in [1,256]
	state        http2priorityNodeState // open | closed | idle
	bytes        int64                  // number of bytes written by this node, or 0 if closed
	subtreeBytes int64                  // sum(node.bytes) of all nodes in this subtree

	// These links form the priority tree.
	parent     *http2priorityNode
	kids       *http2priorityNode // start of the kids list
	prev, next *http2priorityNode // doubly-linked list of siblings
}

func (n *http2priorityNode) setParent(parent *http2priorityNode) {
	if n == parent {
		panic("setParent to self")
	}
	if n.parent == parent {
		return
	}
	// Unlink from current parent.
	if parent := n.parent; parent != nil {
		if n.prev == nil {
			parent.kids = n.next
		} else {
			n.prev.next = n.next
		}
		if n.next != nil {
			n.next.prev = n.prev
		}
	}
	// Link to new parent.
	// If parent=nil, remove n from the tree.
	// Always insert at the head of parent.kids (this is assumed by walkReadyInOrder).
	n.parent = parent
	if parent == nil {
		n.next = nil
		n.prev = nil
	} else {
		n.next = parent.kids
		n.prev = nil
		if n.next != nil {
			n.next.prev = n
		}
		parent.kids = n
	}
}

func (n *http2priorityNode) addBytes(b int64) {
	n.bytes += b
	for ; n != nil; n = n.parent {
		n.subtreeBytes += b
	}
}

// walkReadyInOrder iterates over the tree in priority order, calling f for each node
// with a non-empty write queue. When f returns true, this function returns true and the
// walk halts. tmp is used as scratch space for sorting.
//
// f(n, openParent) takes two arguments: the node to visit, n, and a bool that is true
// if any ancestor p of n is still open (ignoring the root node).
func (n *http2priorityNode) walkReadyInOrder(openParent bool, tmp *[]*http2priorityNode, f func(*http2priorityNode, bool) bool) bool {
	if !n.q.empty() && f(n, openParent) {
		return true
	}
	if n.kids == nil {
		return false
	}

	// Don't consider the root "open" when updating openParent since
	// we can't send data frames on the root stream (only control frames).
	if n.id != 0 {
		openParent = openParent || (n.state == http2priorityNodeOpen)
	}

	// Common case: only one kid or all kids have the same weight.
	// Some clients don't use weights; other clients (like web browsers)
	// use mostly-linear priority trees.
	w := n.kids.weight
	needSort := false
	for k := n.kids.next; k != nil; k = k.next {
		if k.weight != w {
			needSort = true
			break
		}
	}
	if !needSort {
		for k := n.kids; k != nil; k = k.next {
			if k.walkReadyInOrder(openParent, tmp, f) {
				return true
			}
		}
		return false
	}

	// Uncommon case: sort the child nodes. We remove the kids from the parent,
	// then re-insert after sorting so we can reuse tmp for future sort calls.
	*tmp = (*tmp)[:0]
	for n.kids != nil {
		*tmp = append(*tmp, n.kids)
		n.kids.setParent(nil)
	}
	sort.Sort(http2sortPriorityNodeSiblings(*tmp))
	for i := len(*tmp) - 1; i >= 0; i-- {
		(*tmp)[i].setParent(n) // setParent inserts at the head of n.kids
	}
	for k := n.kids; k != nil; k = k.next {
		if k.walkReadyInOrder(openParent, tmp, f) {
			return true
		}
	}
	return false
}

type http2sortPriorityNodeSiblings []*http2priorityNode

func (z http2sortPriorityNodeSiblings) Len() int { return len(z) }

func (z http2sortPriorityNodeSiblings) Swap(i, k int) { z[i], z[k] = z[k], z[i] }

func (z http2sortPriorityNodeSiblings) Less(i, k int) bool {
	// Prefer the subtree that has sent fewer bytes relative to its weight.
	// See sections 5.3.2 and 5.3.4.
	wi, bi := float64(z[i].weight+1), float64(z[i].subtreeBytes)
	wk, bk := float64(z[k].weight+1), float64(z[k].subtreeBytes)
	if bi == 0 && bk == 0 {
		return wi >= wk
	}
	if bk == 0 {
		return false
	}
	return bi/bk <= wi/wk
}

type http2priorityWriteScheduler struct {
	// root is the root of the priority tree, where root.id = 0.
	// The root queues control frames that are not associated with any stream.
	root http2priorityNode

	// nodes maps stream ids to priority tree nodes.
	nodes map[uint32]*http2priorityNode

	// maxID is the maximum stream id in nodes.
	maxID uint32

	// lists of nodes that have been closed or are idle, but are kept in
	// the tree for improved prioritization. When the lengths exceed either
	// maxClosedNodesInTree or maxIdleNodesInTree, old nodes are discarded.
	closedNodes, idleNodes []*http2priorityNode

	// From the config.
	maxClosedNodesInTree int
	maxIdleNodesInTree   int
	writeThrottleLimit   int32
	enableWriteThrottle  bool

	// tmp is scratch space for priorityNode.walkReadyInOrder to reduce allocations.
	tmp []*http2priorityNode

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

func (ws *http2priorityWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	// The stream may be currently idle but cannot be opened or closed.
	if curr := ws.nodes[streamID]; curr != nil {
		if curr.state != http2priorityNodeIdle {
			panic(fmt.Sprintf("stream %d already opened", streamID))
		}
		curr.state = http2priorityNodeOpen
		return
	}

	// RFC 7540, Section 5.3.5:
	//  "All streams are initially assigned a non-exclusive dependency on stream 0x0.
	//  Pushed streams initially depend on their associated stream. In both cases,
	//  streams are assigned a default weight of 16."
	parent := ws.nodes[options.PusherID]
	if parent == nil {
		parent = &ws.root
	}
	n := &http2priorityNode{
		q:      *ws.queuePool.get(),
		id:     streamID,
		weight: http2priorityDefaultWeight,
		state:  http2priorityNodeOpen,
	}
	n.setParent(parent)
	ws.nodes[streamID] = n
	if streamID > ws.maxID {
		ws.maxID = streamID
	}
}

func (ws *http2priorityWriteScheduler) CloseStream(streamID uint32) {
	if streamID == 0 {
		panic("violation of WriteScheduler interface: cannot close stream 0")
	}
	if ws.nodes[streamID] == nil {
		panic(fmt.Sprintf("violation of WriteScheduler interface: unknown stream %d", streamID))
	}
	if ws.nodes[streamID].state != http2priorityNodeOpen {
		panic(fmt.Sprintf("violation of WriteScheduler interface: stream %d already closed", streamID))
	}

	n := ws.nodes[streamID]
	n.state = http2priorityNodeClosed
	n.addBytes(-n.bytes)

	q := n.q
	ws.queuePool.put(&q)
	n.q.s = nil
	if ws.maxClosedNodesInTree > 0 {
		ws.addClosedOrIdleNode(&ws.closedNodes, ws.maxClosedNodesInTree, n)
	} else {
		ws.removeNode(n)
	}
}

func (ws *http2priorityWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {
	if streamID == 0 {
		panic("adjustPriority on root")
	}

	// If streamID does not exist, there are two cases:
	// - A closed stream that has been removed (this will have ID <= maxID)
	// - An idle stream that is being used for "grouping" (this will have ID > maxID)
	n := ws.nodes[streamID]
	if n == nil {
		if streamID <= ws.maxID || ws.maxIdleNodesInTree == 0 {
			return
		}
		ws.maxID = streamID
		n = &http2priorityNode{
			q:      *ws.queuePool.get(),
			id:     streamID,
			weight: http2priorityDefaultWeight,
			state:  http2priorityNodeIdle,
		}
		n.setParent(&ws.root)
		ws.nodes[streamID] = n
		ws.addClosedOrIdleNode(&ws.idleNodes, ws.maxIdleNodesInTree, n)
	}

	// Section 5.3.1: A dependency on a stream that is not currently in the tree
	// results in that stream being given a default priority (Section 5.3.5).
	parent := ws.nodes[priority.StreamDep]
	if parent == nil {
		n.setParent(&ws.root)
		n.weight = http2priorityDefaultWeight
		return
	}

	// Ignore if the client tries to make a node its own parent.
	if n == parent {
		return
	}

	// Section 5.3.3:
	//   "If a stream is made dependent on one of its own dependencies, the
	//   formerly dependent stream is first moved to be dependent on the
	//   reprioritized stream's previous parent. The moved dependency retains
	//   its weight."
	//
	// That is: if parent depends on n, move parent to depend on n.parent.
	for x := parent.parent; x != nil; x = x.parent {
		if x == n {
			parent.setParent(n.parent)
			break
		}
	}

	// Section 5.3.3: The exclusive flag causes the stream to become the sole
	// dependency of its parent stream, causing other dependencies to become
	// dependent on the exclusive stream.
	if priority.Exclusive {
		k := parent.kids
		for k != nil {
			next := k.next
			if k != n {
				k.setParent(n)
			}
			k = next
		}
	}

	n.setParent(parent)
	n.weight = priority.Weight
}

func (ws *http2priorityWriteScheduler) Push(wr http2FrameWriteRequest) {
	var n *http2priorityNode
	if wr.isControl() {
		n = &ws.root
	} else {
		id := wr.StreamID()
		n = ws.nodes[id]
		if n == nil {
			// id is an idle or closed stream. wr should not be a HEADERS or
			// DATA frame. In other case, we push wr onto the root, rather
			// than creating a new priorityNode.
			if wr.DataSize() > 0 {
				panic("add DATA on non-open stream")
			}
			n = &ws.root
		}
	}
	n.q.push(wr)
}

func (ws *http2priorityWriteScheduler) Pop() (wr http2FrameWriteRequest, ok bool) {
	ws.root.walkReadyInOrder(false, &ws.tmp, func(n *http2priorityNode, openParent bool) bool {
		limit := int32(math.MaxInt32)
		if openParent {
			limit = ws.writeThrottleLimit
		}
		wr, ok = n.q.consume(limit)
		if !ok {
			return false
		}
		n.addBytes(int64(wr.DataSize()))
		// If B depends on A and B continuously has data available but A
		// does not, gradually increase the throttling limit to allow B to
		// steal more and more bandwidth from A.
		if openParent {
			ws.writeThrottleLimit += 1024
			if ws.writeThrottleLimit < 0 {
				ws.writeThrottleLimit = math.MaxInt32
			}
		} else if ws.enableWriteThrottle {
			ws.writeThrottleLimit = 1024
		}
		return true
	})
	return wr, ok
}

func (ws *http2priorityWriteScheduler) addClosedOrIdleNode(list *[]*http2priorityNode, maxSize int, n *http2priorityNode) {
	if maxSize == 0 {
		return
	}
	if len(*list) == maxSize {
		// Remove the oldest node, then shift left.
		ws.removeNode((*list)[0])
		x := (*list)[1:]
		copy(*list, x)
		*list = (*list)[:len(x)]
	}
	*list = append(*list, n)
}

func (ws *http2priorityWriteScheduler) removeNode(n *http2priorityNode) {
	for k := n.kids; k != nil; k = k.next {
		k.setParent(n.parent)
	}
	n.setParent(nil)
	delete(ws.nodes, n.id)
}

// NewRandomWriteScheduler constructs a WriteScheduler that ignores HTTP/2
// priorities. Control frames like SETTINGS and PING are written before DATA
// frames, but if no control frames are queued and multiple streams have queued
// HEADERS or DATA frames, Pop selects a ready stream arbitrarily.
func http2NewRandomWriteScheduler() http2WriteScheduler {
	return &http2randomWriteScheduler{sq: make(map[uint32]*http2writeQueue)}
}

type http2randomWriteScheduler struct {
	// zero are frames not associated with a specific stream.
	zero http2writeQueue

	// sq contains the stream-specific queues, keyed by stream ID.
	// When a stream is idle, closed, or emptied, it's deleted
	// from the map.
	sq map[uint32]*http2writeQueue

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

func (ws *http2randomWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	// no-op: idle streams are not tracked
}

func (ws *http2randomWriteScheduler) CloseStream(streamID uint32) {
	q, ok := ws.sq[streamID]
	if !ok {
		return
	}
	delete(ws.sq, streamID)
	ws.queuePool.put(q)
}

func (ws *http2randomWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {
	// no-op: priorities are ignored
}

func (ws *http2randomWriteScheduler) Push(wr http2FrameWriteRequest) {
	if wr.isControl() {
		ws.zero.push(wr)
		return
	}
	id := wr.StreamID()
	q, ok := ws.sq[id]
	if !ok {
		q = ws.queuePool.get()
		ws.sq[id] = q
	}
	q.push(wr)
}

func (ws *http2randomWriteScheduler) Pop() (http2FrameWriteRequest, bool) {
	// Control and RST_STREAM frames first.
	if !ws.zero.empty() {
		return ws.zero.shift(), true
	}
	// Iterate over all non-idle streams until finding one that can be consumed.
	for streamID, q := range ws.sq {
		if wr, ok := q.consume(math.MaxInt32); ok {
			if q.empty() {
				delete(ws.sq, streamID)
				ws.queuePool.put(q)
			}
			return wr, true
		}
	}
	return http2FrameWriteRequest{}, false
}

type http2roundRobinWriteScheduler struct {
	// control contains control frames (SETTINGS, PING, etc.).
	control http2writeQueue

	// streams maps stream ID to a queue.
	streams map[uint32]*http2writeQueue

	// stream queues are stored in a circular linked list.
	// head is the next stream to write, or nil if there are no streams open.
	head *http2writeQueue

	// pool of empty queues for reuse.
	queuePool http2writeQueuePool
}

// newRoundRobinWriteScheduler constructs a new write scheduler.
// The round robin scheduler priorizes control frames
// like SETTINGS and PING over DATA frames.
// When there are no control frames to send, it performs a round-robin
// selection from the ready streams.
func http2newRoundRobinWriteScheduler() http2WriteScheduler {
	ws := &http2roundRobinWriteScheduler{
		streams: make(map[uint32]*http2writeQueue),
	}
	return ws
}

func (ws *http2roundRobinWriteScheduler) OpenStream(streamID uint32, options http2OpenStreamOptions) {
	if ws.streams[streamID] != nil {
		panic(fmt.Errorf("stream %d already opened", streamID))
	}
	q := ws.queuePool.get()
	ws.streams[streamID] = q
	if ws.head == nil {
		ws.head = q
		q.next = q
		q.prev = q
	} else {
		// Queues are stored in a ring.
		// Insert the new stream before ws.head, putting it at the end of the list.
		q.prev = ws.head.prev
		q.next = ws.head
		q.prev.next = q
		q.next.prev = q
	}
}

func (ws *http2roundRobinWriteScheduler) CloseStream(streamID uint32) {
	q := ws.streams[streamID]
	if q == nil {
		return
	}
	if q.next == q {
		// This was the only open stream.
		ws.head = nil
	} else {
		q.prev.next = q.next
		q.next.prev = q.prev
		if ws.head == q {
			ws.head = q.next
		}
	}
	delete(ws.streams, streamID)
	ws.queuePool.put(q)
}

func (ws *http2roundRobinWriteScheduler) AdjustStream(streamID uint32, priority http2PriorityParam) {}

func (ws *http2roundRobinWriteScheduler) Push(wr http2FrameWriteRequest) {
	if wr.isControl() {
		ws.control.push(wr)
		return
	}
	q := ws.streams[wr.StreamID()]
	if q == nil {
		// This is a closed stream.
		// wr should not be a HEADERS or DATA frame.
		// We push the request onto the control queue.
		if wr.DataSize() > 0 {
			panic("add DATA on non-open stream")
		}
		ws.control.push(wr)
		return
	}
	q.push(wr)
}

func (ws *http2roundRobinWriteScheduler) Pop() (http2FrameWriteRequest, bool) {
	// Control and RST_STREAM frames first.
	if !ws.control.empty() {
		return ws.control.shift(), true
	}
	if ws.head == nil {
		return http2FrameWriteRequest{}, false
	}
	q := ws.head
	for {
		if wr, ok := q.consume(math.MaxInt32); ok {
			ws.head = q.next
			return wr, true
		}
		q = q.next
		if q == ws.head {
			break
		}
	}
	return http2FrameWriteRequest{}, false
}
