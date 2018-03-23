package mrt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cloudflare/fgbgp/messages"
	"io"
	"net"
	"time"
)

const (
	TYPE_OSPFV2       = 11
	TYPE_TABLE_DUMP   = 12
	TYPE_TABLE_DUMPV2 = 13

	TYPE_BGP4MP    = 16
	TYPE_BGP4MP_ET = 17

	TYPE_ISIS    = 32
	TYPE_ISIS_ET = 33

	TYPE_OSPFV3    = 48
	TYPE_OSPFV3_ET = 49

	SUBT_TABLE_DUMP_AFI_IPV4 = 1
	SUBT_TABLE_DUMP_AFI_IPV6 = 2

	SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE   = 1
	SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST   = 2
	SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST = 3
	SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST   = 4
	SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST = 5
	SUBT_TABLE_DUMPV2_RIB_GENERIC        = 6

	SUBT_BGP4MP_STATE_CHANGE      = 0
	SUBT_BGP4MP_MESSAGE           = 1
	SUBT_BGP4MP_MESSAGE_AS4       = 4
	SUBT_BGP4MP_STATE_CHANGE_AS4  = 5
	SUBT_BGP4MP_MESSAGE_LOCAL     = 6
	SUBT_BGP4MP_MESSAGE_AS4_LOCAL = 7

	STATE_IDLE        = 1
	STATE_CONNECT     = 2
	STATE_ACTIVE      = 3
	STATE_OPENSENT    = 4
	STATE_OPENCONFIRM = 5
	STATE_ESTABLISHED = 6
)

type Mrt interface {
	Write(io.Writer)
	Len() int
}

func WriteCommonHeader(buf io.Writer, timestamp time.Time, mrttype uint16, subtype uint16, length uint32) {
	binary.Write(buf, binary.BigEndian, uint32(timestamp.Unix()))
	binary.Write(buf, binary.BigEndian, mrttype)
	binary.Write(buf, binary.BigEndian, subtype)
	binary.Write(buf, binary.BigEndian, length)
}

type Peer struct {
	Id  net.IP
	IP  net.IP
	ASN uint32
}

func (p *Peer) Write(buf io.Writer) {
	newip := p.IP
	firstbit := 1
	if tmpip := newip.To4(); tmpip != nil {
		newip = tmpip
		firstbit = 0
	}

	longasn := 1
	if p.ASN <= 0xffff {
		longasn = 0
	}

	firstbyte := byte(longasn<<2 | firstbit)
	binary.Write(buf, binary.BigEndian, firstbyte)

	binary.Write(buf, binary.BigEndian, p.Id.To4())

	binary.Write(buf, binary.BigEndian, newip)
	if longasn == 1 {
		binary.Write(buf, binary.BigEndian, p.ASN)
	} else {
		binary.Write(buf, binary.BigEndian, uint16(p.ASN))
	}
}

func (p *Peer) Len() int {
	iplen := 4
	newip := p.IP
	if tmpip := newip.To4(); tmpip == nil {
		iplen = 16
	}
	longasn := 4
	if p.ASN <= 0xffff {
		longasn = 2
	}
	return 1 + 4 + iplen + longasn
}

type MrtTableDumpV2_PeerIndex struct {
	Timestamp   time.Time
	CollectorId net.IP
	ViewName    string
	Peers       []*Peer
}

func NewMrtTableDumpV2_PeerIndex(collectorid net.IP, viewname string, ts time.Time) *MrtTableDumpV2_PeerIndex {
	return &MrtTableDumpV2_PeerIndex{
		Timestamp:   ts,
		CollectorId: collectorid,
		ViewName:    viewname,
		Peers:       make([]*Peer, 0),
	}
}

func (mrt *MrtTableDumpV2_PeerIndex) AddPeer(id net.IP, asn uint32, ip net.IP) uint16 {
	peer := &Peer{
		Id:  id.To4(),
		IP:  ip,
		ASN: asn,
	}
	mrt.Peers = append(mrt.Peers, peer)
	return uint16(len(mrt.Peers) - 1)
}

func (mrt *MrtTableDumpV2_PeerIndex) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_TABLE_DUMPV2, SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE, uint32(mrt.Len()))
	binary.Write(buf, binary.BigEndian, mrt.CollectorId.To4())
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.ViewName)))
	binary.Write(buf, binary.BigEndian, []byte(mrt.ViewName))
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.Peers)))
	for i := range mrt.Peers {
		mrt.Peers[i].Write(buf)
	}
}

func (mrt *MrtTableDumpV2_PeerIndex) Len() int {
	totallen := 4 + 2 + len(mrt.ViewName) + 2
	for i := range mrt.Peers {
		totallen += mrt.Peers[i].Len()
	}
	return totallen
}

type RibEntry struct {
	PeerIndex  uint16
	OrigTime   time.Time
	Attributes []messages.BGPAttributeIf
}

func (entry *RibEntry) Write(buf io.Writer) {
	binary.Write(buf, binary.BigEndian, entry.PeerIndex)
	binary.Write(buf, binary.BigEndian, uint32(entry.OrigTime.Unix()))

	var size uint16

	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			size += attribute.LenMrt()
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			size += uint16(entry.Attributes[i].Len())
		}
	}

	binary.Write(buf, binary.BigEndian, size)

	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			attribute.WriteMrt(buf)
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			entry.Attributes[i].Write(buf)
		}
	}
}

func (entry *RibEntry) Len() uint32 {
	size := uint32(2 + 4 + 2)
	// To optimize
	for i := range entry.Attributes {
		switch attribute := entry.Attributes[i].(type) {
		case *messages.BGPAttribute_MP_REACH:
			size += uint32(attribute.LenMrt())
		case *messages.BGPAttribute_MP_UNREACH:
		default:
			size += uint32(entry.Attributes[i].Len())
		}

	}
	return size
}

type MrtTableDumpV2_Rib struct {
	Timestamp      time.Time
	SequenceNumber uint32
	Afi            uint16
	Safi           byte
	NLRI           messages.NLRI
	RibEntries     []*RibEntry

	WriteAsAfiSafi bool
}

func NewMrtTableDumpV2_RibGeneric(seqnum uint32, afi uint16, safi byte, nlri messages.NLRI, ts time.Time) *MrtTableDumpV2_Rib {
	return &MrtTableDumpV2_Rib{
		Timestamp:      ts,
		SequenceNumber: seqnum,
		Afi:            afi,
		Safi:           safi,
		NLRI:           nlri,
		RibEntries:     make([]*RibEntry, 0),
	}
}

func NewMrtTableDumpV2_RibAfiSafi(seqnum uint32, afi uint16, safi byte, nlri messages.NLRI, ts time.Time) *MrtTableDumpV2_Rib {
	mrt := NewMrtTableDumpV2_RibGeneric(seqnum, afi, safi, nlri, ts)
	mrt.WriteAsAfiSafi = true
	return mrt
}

func (entry *RibEntry) EntryToUpdate() *messages.BGPMessageUpdate {
	update := &messages.BGPMessageUpdate{
		PathAttributes: entry.Attributes,
	}
	return update
}

func (mrt *MrtTableDumpV2_Rib) ConvertToUpdateIndex(index int) *messages.BGPMessageUpdate {
	re := mrt.RibEntries
	if index >= len(re) {
		return nil
	}
	entry := re[index]
	update := entry.EntryToUpdate()

	if mrt.NLRI.GetAfi() == messages.AFI_IPV6 {
		pa := update.PathAttributes
		var hasreach bool
		for i := range pa {
			switch pai := pa[i].(type) {
			case messages.BGPAttribute_MP_REACH:
				// Check NLRI already in
				var hasipinreach bool
				hasreach = true

				mpnlri := pai.NLRI
				for j := range mpnlri {
					if mrt.NLRI.Equals(mpnlri[j]) {
						hasipinreach = true
						break
					}
				}

				if !hasipinreach {
					pai.NLRI = append(pai.NLRI, mrt.NLRI)
				}

			}
		}
		if !hasreach {
			attr := &messages.BGPAttribute_MP_REACH{
				NLRI: []messages.NLRI{mrt.NLRI},
			}
			update.PathAttributes = append(update.PathAttributes, attr)
		}
	} else {
		update.NLRI = []messages.NLRI{mrt.NLRI}
	}
	return update
}
func (mrt *MrtTableDumpV2_Rib) ConvertToUpdate() []*messages.BGPMessageUpdate {
	updates := make([]*messages.BGPMessageUpdate, 0)
	re := mrt.RibEntries
	for i := range re {
		update := mrt.ConvertToUpdateIndex(i)
		if update != nil {
			updates = append(updates, update)
		}
	}
	return updates
}

func (mrt *MrtTableDumpV2_Rib) AddEntry(peerindex uint16, origtime time.Time, attributes []messages.BGPAttributeIf) {
	entry := &RibEntry{
		PeerIndex:  peerindex,
		OrigTime:   origtime,
		Attributes: attributes,
	}
	mrt.RibEntries = append(mrt.RibEntries, entry)
}

func (mrt *MrtTableDumpV2_Rib) GetSubtype() (bool, uint16) {
	subt := uint16(SUBT_TABLE_DUMPV2_RIB_GENERIC)
	force_generic := true

	if mrt.WriteAsAfiSafi {
		if mrt.Afi == messages.AFI_IPV4 && mrt.Safi == messages.SAFI_UNICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST
		} else if mrt.Afi == messages.AFI_IPV4 && mrt.Safi == messages.SAFI_MULTICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST
		} else if mrt.Afi == messages.AFI_IPV6 && mrt.Safi == messages.SAFI_UNICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST
		} else if mrt.Afi == messages.AFI_IPV6 && mrt.Safi == messages.SAFI_MULTICAST {
			force_generic = false
			subt = SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST
		}
	}
	return force_generic, subt
}

func (mrt *MrtTableDumpV2_Rib) Write(buf io.Writer) {
	force_generic, subt := mrt.GetSubtype()

	WriteCommonHeader(buf, mrt.Timestamp, TYPE_TABLE_DUMPV2, subt, uint32(mrt.Len()))
	if force_generic {
		binary.Write(buf, binary.BigEndian, mrt.Afi)
		binary.Write(buf, binary.BigEndian, mrt.Safi)
	}

	binary.Write(buf, binary.BigEndian, mrt.SequenceNumber)
	binary.Write(buf, binary.BigEndian, mrt.NLRI.Bytes(false))
	binary.Write(buf, binary.BigEndian, uint16(len(mrt.RibEntries)))
	for i := range mrt.RibEntries {
		mrt.RibEntries[i].Write(buf)
	}
}

func (mrt *MrtTableDumpV2_Rib) Len() int {
	force_generic, _ := mrt.GetSubtype()
	size := 4 + len(mrt.NLRI.Bytes(false)) + 2
	if force_generic {
		size += 2
	}
	for i := range mrt.RibEntries {
		size += int(mrt.RibEntries[i].Len())
	}
	return size
}

type MrtBGP4MP_Msg_AS4 struct {
	Timestamp  time.Time
	PeerAS     uint32
	LocalAS    uint32
	IfaceIndex uint16
	PeerIP     net.IP
	LocalIP    net.IP
	Message    messages.SerializableInterface
}

type MrtBGP4MP_StateChange_AS4 struct {
	Timestamp  time.Time
	PeerAS     uint32
	LocalAS    uint32
	IfaceIndex uint16
	PeerIP     net.IP
	LocalIP    net.IP
	OldState   uint16
	NewState   uint16
}

func NewMrtBGP4MP_StateChange_AS4(peeras uint32, localas uint32, iface uint16, peerip net.IP, localip net.IP, oldstate uint16, newstate uint16) *MrtBGP4MP_StateChange_AS4 {
	return &MrtBGP4MP_StateChange_AS4{
		Timestamp:  time.Now().UTC(),
		PeerAS:     peeras,
		LocalAS:    localas,
		IfaceIndex: iface,
		PeerIP:     peerip,
		LocalIP:    localip,
		OldState:   oldstate,
		NewState:   newstate,
	}
}

func (mrt *MrtBGP4MP_StateChange_AS4) IsIPv4() bool {
	return mrt.PeerIP.To4() != nil
}

func (mrt *MrtBGP4MP_StateChange_AS4) Len() int {
	ipsize := 4
	if !mrt.IsIPv4() {
		ipsize = 16
	}
	return 4 + 4 + 2 + 2 + 2*ipsize + 2 + 2
}

func (mrt *MrtBGP4MP_StateChange_AS4) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_BGP4MP, SUBT_BGP4MP_STATE_CHANGE_AS4, uint32(mrt.Len()))

	binary.Write(buf, binary.BigEndian, mrt.PeerAS)
	binary.Write(buf, binary.BigEndian, mrt.LocalAS)

	binary.Write(buf, binary.BigEndian, mrt.IfaceIndex)
	if mrt.IsIPv4() {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV4))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP.To4())
		binary.Write(buf, binary.BigEndian, mrt.LocalIP.To4())
	} else {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV6))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP)
		binary.Write(buf, binary.BigEndian, mrt.LocalIP)
	}

	binary.Write(buf, binary.BigEndian, mrt.OldState)
	binary.Write(buf, binary.BigEndian, mrt.NewState)
}

func NewMrtBGP4MP_Msg_AS4(peeras uint32, localas uint32, iface uint16, peerip net.IP, localip net.IP, message messages.SerializableInterface) *MrtBGP4MP_Msg_AS4 {
	return &MrtBGP4MP_Msg_AS4{
		Timestamp:  time.Now().UTC(),
		PeerAS:     peeras,
		LocalAS:    localas,
		IfaceIndex: iface,
		PeerIP:     peerip,
		LocalIP:    localip,
		Message:    message,
	}
}

func (mrt *MrtBGP4MP_Msg_AS4) IsIPv4() bool {
	return mrt.PeerIP.To4() != nil
}

func (mrt *MrtBGP4MP_Msg_AS4) Len() int {
	ipsize := 4
	if !mrt.IsIPv4() {
		ipsize = 16
	}
	return 4 + 4 + 2 + 2 + 2*ipsize + mrt.Message.Len()
}

func (mrt *MrtBGP4MP_Msg_AS4) Write(buf io.Writer) {
	WriteCommonHeader(buf, mrt.Timestamp, TYPE_BGP4MP, SUBT_BGP4MP_MESSAGE_AS4, uint32(mrt.Len()))

	binary.Write(buf, binary.BigEndian, mrt.PeerAS)
	binary.Write(buf, binary.BigEndian, mrt.LocalAS)

	binary.Write(buf, binary.BigEndian, mrt.IfaceIndex)
	if mrt.IsIPv4() {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV4))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP.To4())
		binary.Write(buf, binary.BigEndian, mrt.LocalIP.To4())
	} else {
		binary.Write(buf, binary.BigEndian, uint16(messages.AFI_IPV6))
		binary.Write(buf, binary.BigEndian, mrt.PeerIP)
		binary.Write(buf, binary.BigEndian, mrt.LocalIP)
	}
	mrt.Message.Write(buf)
}

func DecodeBGP4MP(buf io.Reader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	switch subtype {
	case SUBT_BGP4MP_MESSAGE_AS4:
		var peeras uint32
		var localas uint32
		var ifaceindex uint16
		var afi uint16
		binary.Read(buf, binary.BigEndian, peeras)
		binary.Read(buf, binary.BigEndian, localas)
		binary.Read(buf, binary.BigEndian, ifaceindex)
		binary.Read(buf, binary.BigEndian, afi)
		var peerip []byte
		var localip []byte
		sizeip := 4
		if afi == messages.AFI_IPV6 {
			sizeip = 16
		}
		peerip = make([]byte, sizeip)
		localip = make([]byte, sizeip)
		binary.Read(buf, binary.BigEndian, peerip)
		binary.Read(buf, binary.BigEndian, localip)

		msgsize := length - uint32(4+4+2+2+2*(sizeip))
		if msgsize < 0 {
			return nil, errors.New("DecodeBGP4MP: cannot decode message with negative length")
		}
		msg := make([]byte, msgsize)
		// Do progressive read or replace parsepacketheader with io.Reader
		binary.Read(buf, binary.BigEndian, msg)

		bgptype, bgplen, err1 := messages.ParsePacketHeader(msg)
		if err1 != nil {
			return nil, err1
		}
		pktd, err2 := messages.ParsePacket(bgptype, msg[19:19+bgplen])

		mrt := &MrtBGP4MP_Msg_AS4{
			Timestamp:  timestamp,
			PeerAS:     peeras,
			LocalAS:    localas,
			IfaceIndex: ifaceindex,
			PeerIP:     net.IP(peerip),
			LocalIP:    net.IP(localip),
			Message:    pktd,
		}

		return mrt, err2
	case SUBT_BGP4MP_STATE_CHANGE_AS4:
		var peeras uint32
		var localas uint32
		var ifaceindex uint16
		var afi uint16
		binary.Read(buf, binary.BigEndian, peeras)
		binary.Read(buf, binary.BigEndian, localas)
		binary.Read(buf, binary.BigEndian, ifaceindex)
		binary.Read(buf, binary.BigEndian, afi)
		var peerip []byte
		var localip []byte
		sizeip := 4
		if afi == messages.AFI_IPV6 {
			sizeip = 16
		}
		peerip = make([]byte, sizeip)
		localip = make([]byte, sizeip)
		binary.Read(buf, binary.BigEndian, peerip)
		binary.Read(buf, binary.BigEndian, localip)
		var oldstate uint16
		var newstate uint16
		binary.Read(buf, binary.BigEndian, oldstate)
		binary.Read(buf, binary.BigEndian, newstate)

		mrt := &MrtBGP4MP_StateChange_AS4{
			Timestamp:  timestamp,
			PeerAS:     peeras,
			LocalAS:    localas,
			IfaceIndex: ifaceindex,
			PeerIP:     net.IP(peerip),
			LocalIP:    net.IP(localip),
			OldState:   oldstate,
			NewState:   newstate,
		}

		return mrt, nil
	default:
		return nil, errors.New(fmt.Sprintf("Decoding of subtype %v of BGP4MP not implemented", subtype))
	}
	return nil, nil
}

func DecodeNLRI(buf io.Reader, afi uint16, safi byte) (messages.NLRI, error) {
	if afi != messages.AFI_IPV4 && afi != messages.AFI_IPV6 {
		return nil, errors.New(fmt.Sprintf("Could not decode NLRI for Afi: %v", afi))
	}
	if safi != messages.SAFI_UNICAST && safi != messages.SAFI_MULTICAST {
		return nil, errors.New(fmt.Sprintf("Could not decode NLRI for Safi: %v", safi))
	}

	var l byte
	binary.Read(buf, binary.BigEndian, &l)

	size := l / 8
	if l%8 != 0 {
		size++
	}
	b := make([]byte, size)
	binary.Read(buf, binary.BigEndian, &b)

	newb := append([]byte{l}, b...)
	nlri, err := messages.ParseNLRI(newb, afi, safi, false)

	if len(nlri) == 1 {
		return nlri[0], err
	} else {
		return nil, errors.New(fmt.Sprintf("Could not decode NLRI %v (%v/%v) (number of results != 1): %v", newb, afi, safi, err))
	}
}

func DecodeAttributes(buf io.Reader, attrlen uint16) ([]messages.BGPAttributeIf, error) {
	b := make([]byte, attrlen)
	binary.Read(buf, binary.BigEndian, b)
	return messages.ParsePathAttribute(b, nil, false)
}

func DecodeRibEntries(buf io.Reader) (*RibEntry, error) {
	var peerindex uint16
	var origints uint32
	var attrlen uint16
	binary.Read(buf, binary.BigEndian, &peerindex)
	binary.Read(buf, binary.BigEndian, &origints)
	binary.Read(buf, binary.BigEndian, &attrlen)
	attrs, err := DecodeAttributes(buf, attrlen)
	origintsP := time.Unix(int64(origints), 0)
	re := &RibEntry{
		OrigTime:   origintsP,
		PeerIndex:  peerindex,
		Attributes: attrs,
	}
	return re, err
}

func DecodeBGP4TD2RIBSpec(buf io.Reader, subtype uint16, timestamp time.Time) (Mrt, error) {
	var afi uint16
	var safi byte
	if subtype == SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST {
		afi = messages.AFI_IPV4
		safi = messages.SAFI_UNICAST
	} else if subtype == SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST {
		afi = messages.AFI_IPV6
		safi = messages.SAFI_UNICAST
	} else if subtype == SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST {
		afi = messages.AFI_IPV4
		safi = messages.SAFI_MULTICAST
	} else if subtype == SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST {
		afi = messages.AFI_IPV6
		safi = messages.SAFI_MULTICAST
	} else {
		return nil, errors.New("Cannot decode as Rib Afi/Safi specific")
	}

	var seqnum uint32
	var preflen uint8
	var prefix []byte
	binary.Read(buf, binary.BigEndian, &seqnum)
	binary.Read(buf, binary.BigEndian, &preflen)

	size := preflen / 8
	if preflen%8 != 0 {
		size++
	}
	prefix = make([]byte, size)
	binary.Read(buf, binary.BigEndian, &prefix)

	newb := append([]byte{preflen}, prefix...)
	nlri, err := messages.ParseNLRI(newb, afi, safi, false)

	mrt := &MrtTableDumpV2_Rib{
		Timestamp:      timestamp,
		Afi:            afi,
		Safi:           safi,
		SequenceNumber: seqnum,
		WriteAsAfiSafi: true,
	}

	if len(nlri) == 1 {
		mrt.NLRI = nlri[0]
	} else {
		return mrt, errors.New(fmt.Sprintf("Could not decode NLRI %v (%v/%v) (number of results != 1): %v", newb, afi, safi, err))
	}

	if err != nil {
		return mrt, err
	}

	var entrycount uint16
	binary.Read(buf, binary.BigEndian, &entrycount)
	entries := make([]*RibEntry, entrycount)
	var errentry error
	for i := 0; i < int(entrycount); i++ {
		var entry *RibEntry
		entry, errentry = DecodeRibEntries(buf)
		entries[i] = entry
	}
	mrt.RibEntries = entries
	return mrt, errentry
}

func DecodeBGP4TD2(buf io.Reader, timestamp time.Time, subtype uint16, length uint32) (Mrt, error) {
	switch subtype {
	case SUBT_TABLE_DUMPV2_PEER_INDEX_TABLE:
		collid := make([]byte, 4)
		var viewnamelen uint16
		var peercount uint16
		var viewname []byte
		var peers []*Peer

		binary.Read(buf, binary.BigEndian, &collid)
		binary.Read(buf, binary.BigEndian, &viewnamelen)

		viewname = make([]byte, viewnamelen)

		binary.Read(buf, binary.BigEndian, &viewname)
		binary.Read(buf, binary.BigEndian, &peercount)

		peers = make([]*Peer, peercount)

		for i := 0; i < int(peercount); i++ {
			var peertype uint8
			bgpid := make([]byte, 4)
			var asn uint32
			var peerip []byte

			binary.Read(buf, binary.BigEndian, &peertype)
			binary.Read(buf, binary.BigEndian, &bgpid)

			sizeip := 4
			sizeasn := 2
			if peertype&0x2 != 0 {
				sizeasn = 4
			}
			if peertype&0x1 != 0 {
				sizeip = 16
			}
			tmpasn := make([]byte, sizeasn)
			peerip = make([]byte, sizeip)

			binary.Read(buf, binary.BigEndian, &peerip)
			binary.Read(buf, binary.BigEndian, &tmpasn)

			if sizeasn == 2 {
				asn = uint32(binary.BigEndian.Uint16(tmpasn))
			} else if sizeasn == 4 {
				asn = binary.BigEndian.Uint32(tmpasn)
			}

			curpeer := &Peer{
				Id:  bgpid,
				IP:  peerip,
				ASN: asn,
			}

			peers[i] = curpeer
		}

		mrt := &MrtTableDumpV2_PeerIndex{
			Timestamp:   timestamp,
			CollectorId: collid,
			ViewName:    string(viewname),
			Peers:       peers,
		}
		return mrt, nil

	case SUBT_TABLE_DUMPV2_RIB_GENERIC:
		var seqnum uint32
		var afi uint16
		var safi byte
		binary.Read(buf, binary.BigEndian, &seqnum)
		binary.Read(buf, binary.BigEndian, &afi)
		binary.Read(buf, binary.BigEndian, &safi)

		nlri, err := DecodeNLRI(buf, afi, safi)

		mrt := &MrtTableDumpV2_Rib{
			Timestamp:      timestamp,
			Afi:            afi,
			Safi:           safi,
			SequenceNumber: seqnum,
			NLRI:           nlri,
		}
		if err != nil {
			return mrt, err
		}

		var entrycount uint16
		binary.Read(buf, binary.BigEndian, &entrycount)
		entries := make([]*RibEntry, entrycount)
		var errentry error
		for i := 0; i < int(entrycount); i++ {
			var entry *RibEntry
			entry, errentry = DecodeRibEntries(buf)
			entries[i] = entry
		}
		mrt.RibEntries = entries
		return mrt, errentry
	case SUBT_TABLE_DUMPV2_RIB_IPV4_UNICAST:
		return DecodeBGP4TD2RIBSpec(buf, subtype, timestamp)
	case SUBT_TABLE_DUMPV2_RIB_IPV6_UNICAST:
		return DecodeBGP4TD2RIBSpec(buf, subtype, timestamp)
	case SUBT_TABLE_DUMPV2_RIB_IPV4_MULTICAST:
		return DecodeBGP4TD2RIBSpec(buf, subtype, timestamp)
	case SUBT_TABLE_DUMPV2_RIB_IPV6_MULTICAST:
		return DecodeBGP4TD2RIBSpec(buf, subtype, timestamp)
	default:
		return nil, errors.New(fmt.Sprintf("Decoding of subtype %v of BGP4TableDumpV2 not implemented", subtype))
	}
	return nil, nil
}

func DecodeSingle(buf io.Reader) (Mrt, error) {
	var timestamp uint32
	var mrttype uint16
	var mrtsubtype uint16
	var mrtlength uint32

	binary.Read(buf, binary.BigEndian, &timestamp)
	binary.Read(buf, binary.BigEndian, &mrttype)
	binary.Read(buf, binary.BigEndian, &mrtsubtype)
	binary.Read(buf, binary.BigEndian, &mrtlength)

	timestampP := time.Unix(int64(timestamp), 0)

	content := make([]byte, mrtlength)
	binary.Read(buf, binary.BigEndian, &content)
	tmpbuf := bytes.NewBuffer(content)

	var mrt Mrt
	var err error
	switch mrttype {
	case TYPE_BGP4MP:
		mrt, err = DecodeBGP4MP(tmpbuf, timestampP, mrtsubtype, mrtlength)
	case TYPE_TABLE_DUMPV2:
		mrt, err = DecodeBGP4TD2(tmpbuf, timestampP, mrtsubtype, mrtlength)
	default:
		err = errors.New(fmt.Sprintf("Decoding of type %v not implemented", mrttype))
	}

	return mrt, err
}
