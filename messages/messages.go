package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"time"
)

var (
	errCodeToStr = map[int]string{
		1: "Message Header Error",
		2: "OPEN Message Error",
		3: "UPDATE Message Error",
		4: "Hold Timer Expired",
		5: "Finite State Machine Error",
		6: "Cease",
	}
	errSubCodeToStr = map[int]map[int]string{
		1: map[int]string{
			1: "Connection Not Synchronized.",
			2: "Bad Message Length.",
			3: "Bad Message Type.",
		},
		2: map[int]string{
			1: "Unsupported Version Number.",
			2: "Bad Peer AS.",
			3: "Bad BGP Identifier.",
			4: "Unsupported Optional Parameter.",
			6: "Unacceptable Hold Time.",
		},
		3: map[int]string{
			1:  "Malformed Attribute List.",
			2:  "Unrecognized Well-known Attribute.",
			3:  "Missing Well-known Attribute.",
			4:  "Attribute Flags Error.",
			5:  "Attribute Length Error.",
			6:  "Invalid ORIGIN Attribute.",
			8:  "Invalid NEXT_HOP Attribute.",
			9:  "Optional Attribute Error.",
			10: "Invalid Network Field.",
			11: "Malformed AS_PATH.",
		},
	}
	CapaDescr = map[int]string{
		1:  "Multiprotocol Extensions for BGP-4",
		2:  "Route Refresh Capability for BGP-4",
		3:  "Outbound Route Filtering Capability",
		4:  "Multiple routes to a destination capability",
		5:  "Extended Next Hop Encoding",
		6:  "BGP-Extended Message",
		7:  "BGPsec Capability",
		8:  "Multiple Labels Capability",
		64: "Graceful Restart Capability",
		65: "Support for 4-octet AS number capability",
		66: "Deprecated (2003-03-06)",
		67: "Support for Dynamic Capability (capability specific)",
		68: "Multisession BGP Capability",
		69: "ADD-PATH Capability",
		70: "Enhanced Route Refresh Capability",
		71: "Long-Lived Graceful Restart (LLGR) Capability",
		72: "Unassigned",
		73: "FQDN Capability",
	}
	BgpAttributes = map[int]string{
		0:                 "Reserved",
		ATTRIBUTE_ORIGIN:  "ORIGIN",
		ATTRIBUTE_ASPATH:  "AS_PATH",
		ATTRIBUTE_NEXTHOP: "NEXT_HOP",
		ATTRIBUTE_MED:     "MULTI_EXIT_DISC",
		ATTRIBUTE_LOCPREF: "LOCAL_PREF",
		6:                 "ATOMIC_AGGREGATE",
		7:                 "AGGREGATOR",
		ATTRIBUTE_COMMUNITIES: "COMMUNITY",
		9:                 "ORIGINATOR_ID",
		10:                "CLUSTER_LIST",
		11:                "DPA (deprecated)",
		12:                "ADVERTISER  (historic) (deprecated)",
		13:                "RCID_PATH / CLUSTER_ID (Historic) (deprecated)",
		ATTRIBUTE_REACH:   "MP_REACH_NLRI",
		ATTRIBUTE_UNREACH: "MP_UNREACH_NLRI",
		16:                "EXTENDED COMMUNITIES",
		ATTRIBUTE_AS4PATH: "AS4_PATH",
		18:                "AS4_AGGREGATOR",
		19:                "SAFI Specific Attribute (SSA) (deprecated)",
		20:                "Connector Attribute (deprecated)",
		21:                "AS_PATHLIMIT (deprecated)",
		22:                "PMSI_TUNNEL",
		23:                "Tunnel Encapsulation Attribute",
		24:                "Traffic Engineering",
		25:                "IPv6 Address Specific Extended Community",
		26:                "AIGP",
		27:                "PE Distinguisher Labels",
		28:                "BGP Entropy Label Capability Attribute (deprecated)",
		29:                "BGP-LS Attribute",
		30:                "Deprecated",
		31:                "Deprecated",
		32:                "LARGE_COMMUNITY",
		33:                "BGPsec_Path",
		34:                "BGP Community Container Attribute",
		40:                "BGP Prefix-SID",
		128:               "ATTR_SET",
		129:               "Deprecated",
		241:               "Deprecated",
		242:               "Deprecated",
		243:               "Deprecated",
	}
	Afi = map[string]uint16{
		"ipv4": AFI_IPV4,
		"ipv6": AFI_IPV6,
	}
	AfiToStr = map[uint16]string{
		AFI_IPV4: "ipv4",
		AFI_IPV6: "ipv6",
	}
	Safi = map[string]byte{
		"unicast":   SAFI_UNICAST,
		"multicast": SAFI_MULTICAST,
	}
	SafiToStr = map[byte]string{
		SAFI_UNICAST:   "unicast",
		SAFI_MULTICAST: "multicast",
	}
)

const (
	MESSAGE_OPEN         = 1
	MESSAGE_UPDATE       = 2
	MESSAGE_NOTIFICATION = 3
	MESSAGE_KEEPALIVE    = 4
	MESSAGE_ROUTEREFRESH = 5

	CAPA_MP      = 1
	CAPA_ASN     = 65
	CAPA_ADDPATH = 69
	CAPA_RR      = 2

	ATTRIBUTE_ORIGIN           = 1
	ATTRIBUTE_ASPATH           = 2
	ATTRIBUTE_NEXTHOP          = 3
	ATTRIBUTE_MED              = 4
	ATTRIBUTE_LOCPREF          = 5
	ATTRIBUTE_ATOMIC_AGGREGATE = 6
	ATTRIBUTE_AGGREGATOR       = 7
	ATTRIBUTE_COMMUNITIES      = 8
	ATTRIBUTE_REACH            = 14
	ATTRIBUTE_UNREACH          = 15
	ATTRIBUTE_AS4PATH          = 17

	ATTRIBUTE_TRANSITIVE    = 0x40
	ATTRIBUTE_TRANSITIVEOPT = 0xC0
	ATTRIBUTE_OPTIONAL      = 0x80
	ATTRIBUTE_EXTENDED      = 0x16

	PARAMETER_CAPA = 2

	AFI_IPV4 = 1
	AFI_IPV6 = 2

	SAFI_UNICAST   = 1
	SAFI_MULTICAST = 2
)

type NLRI interface {
	GetAfi() uint16
	GetSafi() byte
	Len(addpath bool) int
	Write(w io.Writer, addpath bool)
	Bytes(addpath bool) []byte
	String() string
	Equals(nlri NLRI) bool
}

type NLRI_IPPrefix struct {
	Prefix net.IPNet
	PathId uint32
}

func (m NLRI_IPPrefix) Equals(mm NLRI) bool {
	mmc, ok := mm.(NLRI_IPPrefix)
	if ok && mmc.GetAfi() == m.GetAfi() && mmc.GetSafi() == m.GetSafi() &&
		mmc.PathId == m.PathId &&
		mmc.Prefix.IP.Equal(m.Prefix.IP) &&
		bytes.Equal(mmc.Prefix.Mask, m.Prefix.Mask) {
		return true
	}

	return false
}

func (m NLRI_IPPrefix) GetAfi() uint16 {
	if m.Prefix.IP.To4() != nil {
		return AFI_IPV4
	} else if m.Prefix.IP.To16() != nil {
		return AFI_IPV6
	} else {
		return 0
	}
}

func (n NLRI_IPPrefix) GetSafi() byte {
	return SAFI_UNICAST
}

func (n NLRI_IPPrefix) String() string {
	return fmt.Sprintf("PathId: %v / Prefix: %v", n.PathId, n.Prefix.String())
}

func (n NLRI_IPPrefix) Len(addpath bool) int {
	add := 0
	if addpath {
		add = 4
	}
	return add + 1 + n.GetSplitLen()
}

func (n NLRI_IPPrefix) GetSplitLen() int {
	ones, _ := n.Prefix.Mask.Size()
	add := 0
	if ones%8 != 0 {
		add = 1
	}
	return ones/8 + add
}

func (n NLRI_IPPrefix) Write(w io.Writer, addpath bool) {
	if addpath {
		binary.Write(w, binary.BigEndian, n.PathId)
	}

	ones, _ := n.Prefix.Mask.Size()
	binary.Write(w, binary.BigEndian, byte(ones))
	length := n.GetSplitLen()

	for i := 0; i < length; i++ {
		binary.Write(w, binary.BigEndian, n.Prefix.IP[i])
	}
}

func (n NLRI_IPPrefix) Bytes(addpath bool) []byte {
	buf := make([]byte, 0)
	w := bytes.NewBuffer(buf)

	n.Write(w, addpath)

	return w.Bytes()
}

type AfiSafi struct {
	Afi  uint16
	Safi byte
}

/*
type NLRI struct {
    Prefix net.IPNet
    PathId uint32
}*/

type SerializableInterface interface {
	//Bytes() []byte
	String() string
	Write(w io.Writer)
	Len() int
}

type BGPMessageHead struct {
	Received time.Time
}

type BGPMessageKeepAlive struct {
	BGPMessageHead
}

type BGPMessageRouteRefresh struct {
	BGPMessageHead
	AfiSafi AfiSafi
}

type BGPMessageNotification struct {
	BGPMessageHead
	ErrorCode    byte
	ErrorSubcode byte
	Data         []byte
}

func (m AfiSafi) String() string {
	return fmt.Sprintf("%v-%v (%v) (%v)", AfiToStr[m.Afi], SafiToStr[m.Safi], m.Afi, m.Safi)
}

func (ap AddPath) EqualsAfiSafi(comp AddPath) bool {
	return ap.Afi == comp.Afi && ap.Safi == comp.Safi
}

func (p AddPath) String() string {
	return fmt.Sprintf("Afi: %v-%v (%v) (%v) / TxRx: %v", AfiToStr[p.Afi], SafiToStr[p.Safi], p.Afi, p.Safi, p.TxRx)
}

func (m BGPMessageKeepAlive) String() string {
	str := "BGP KeepAlive\n"
	return str
}

func (m BGPMessageKeepAlive) Write(bw io.Writer) {
	WriteBGPHeader(MESSAGE_KEEPALIVE, 0, bw)
}

func (m BGPMessageKeepAlive) Len() int {
	return GetBGPHeaderLen()
}

func (m BGPMessageKeepAlive) Bytes() []byte {
	buf := make([]byte, 0)
	bw := bytes.NewBuffer(buf)

	m.Write(bw)

	return bw.Bytes()
}

func (m BGPMessageRouteRefresh) String() string {
	str := fmt.Sprintf("BGP Route Refresh %v\n", m.AfiSafi.String())
	return str
}

func (m BGPMessageRouteRefresh) Len() int {
	return GetBGPHeaderLen() + 4
}

func (m BGPMessageRouteRefresh) Write(bw io.Writer) {
	WriteBGPHeader(MESSAGE_ROUTEREFRESH, 4, bw)
	binary.Write(bw, binary.BigEndian, m.AfiSafi.Afi)
	binary.Write(bw, binary.BigEndian, byte(0))
	binary.Write(bw, binary.BigEndian, m.AfiSafi.Safi)
}

/*
func (m NLRI) String() string {
    return fmt.Sprintf("PathId: %v / Prefix: %v", m.PathId, m.Prefix.String())
}

func (n NLRI) Bytes(addpath bool) []byte {
    buf := make([]byte, 0)
    bw := bytes.NewBuffer(buf)

    if addpath {
        binary.Write(bw, binary.BigEndian, n.PathId)
    }

    ones, _ := n.Prefix.Mask.Size()
    bw.WriteByte(byte(ones))

    add := 0
    if ones%8 != 0 {
        add = 1
    }
    length := ones/8 + add

    for i := 0; i<length; i++ {
        bw.WriteByte(n.Prefix.IP[i])
    }

    return bw.Bytes()
}*/

func (m *BGPMessageNotification) String() string {
	str := "BGP Notification: %v (%v): %v (%v): %v"
	desc := errCodeToStr[int(m.ErrorCode)]
	sub := errSubCodeToStr[int(m.ErrorCode)]
	var descsub string
	if sub != nil {
		descsub = errSubCodeToStr[int(m.ErrorCode)][int(m.ErrorSubcode)]
	}
	return fmt.Sprintf(str, desc, m.ErrorCode, descsub, m.ErrorSubcode, m.Data)
}

func (m BGPMessageNotification) Len() int {
	return 0
}

func (m BGPMessageNotification) Write(bw io.Writer) {

}

func InAfiSafi(afi uint16, safi byte, list []AfiSafi) bool {
	for i := range list {
		if list[i].Afi == afi && list[i].Safi == safi {
			return true
		}
	}
	return false
}

func ParsePacketHeader(b []byte) (byte, uint16, error) {
	if len(b) >= 19 {
		length := uint16(b[16])<<8 | uint16(b[17])
		if length < 19 || length > 4096 {
			return 0, 0, errors.New(fmt.Sprintf("BGP Packet parser: wrong length: 19: !<= %v !<= 4096", length))
		}
		if length < 19 {
			return 0, 0, errors.New(fmt.Sprintf("BGP Packet parser: wrong length: 19: !<= %v", length))
		}

		length -= 19
		bgptype := b[18]
		//log.Debugf("ParsePacketHeader: len: %v type: %v", length, bgptype)
		return bgptype, length, nil
	} else {
		return 0, 0, errors.New(fmt.Sprintf("BGP Packet parser: wrong header size: %v < 19", len(b)))
	}
}

func ParseKeepAlive() (*BGPMessageKeepAlive, error) {
	return &BGPMessageKeepAlive{}, nil
}

func ParseNotification(b []byte) (*BGPMessageNotification, error) {
	if len(b) < 2 {
		return nil, errors.New(fmt.Sprintf("ParseNotification: wrong open size: %v < 2", len(b)))
	}

	errCode := b[0]
	errSubcode := b[1]
	errData := make([]byte, 0)
	if len(b) >= 2 {
		errData = b[2:]
	}

	r := &BGPMessageNotification{
		BGPMessageHead{time.Now()},
		errCode,
		errSubcode,
		errData,
	}

	log.Errorf("ParseNotification: %v", r.String())
	return r, nil
}

func ParsePacket(bgptype byte, b []byte) (SerializableInterface, error) {
	switch bgptype {
	case MESSAGE_OPEN:
		openmsg, err := ParseOpen(b)
		return openmsg, err
	case MESSAGE_UPDATE:
		return ParseUpdate(b, nil, false)
	case MESSAGE_NOTIFICATION:
		return ParseNotification(b)
	case MESSAGE_KEEPALIVE:
		return ParseKeepAlive()
	default:
		return nil, errors.New(fmt.Sprintf("Unknown packet type: %v", bgptype))
	}
	return nil, nil
}

func CraftKeepAliveMessage() *BGPMessageKeepAlive {
	return &BGPMessageKeepAlive{}
}

func GetBGPHeaderLen() int {
	return 19
}

func WriteBGPHeader(bgptype byte, size uint16, bw io.Writer) {
	bw.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	binary.Write(bw, binary.BigEndian, uint16(19+size))
	binary.Write(bw, binary.BigEndian, bgptype)
}
