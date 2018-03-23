package rib

import (
	"github.com/cloudflare/fgbgp/messages"
	"github.com/cloudflare/fgbgp/mrt"
	"github.com/lspgn/lctrie"
	"net"
	"sync"
	"time"
	//"fmt"
)

type LcRib struct {
	PrefixTable      *lctrie.Trie
	Prefix6Table     *lctrie.Trie
	SyncPrefixTable  *sync.RWMutex
	SyncPrefix6Table *sync.RWMutex
	Countv4          int
	Countv6          int
}

func NewLcRib() *LcRib {
	return &LcRib{
		PrefixTable:      lctrie.New(),
		Prefix6Table:     lctrie.New(),
		SyncPrefixTable:  &sync.RWMutex{},
		SyncPrefix6Table: &sync.RWMutex{},
	}
}

type dumpWalkArgs struct {
	f       WalkMrt
	peerid  uint16
	iter    uint32
	isv6    bool
	afi     uint16
	safi    byte
	curtime time.Time
}

type Walk func(net.IPNet, *messages.BGPMessageUpdate) bool
type WalkMrt func(*mrt.MrtTableDumpV2_Rib) bool

func (args *dumpWalkArgs) dumpWalk(prefix net.IPNet, msg *messages.BGPMessageUpdate) bool {
	dump := mrt.NewMrtTableDumpV2_RibAfiSafi(args.iter, args.afi, args.safi, messages.NLRI_IPPrefix{Prefix: prefix}, args.curtime)
	dump.AddEntry(args.peerid, args.curtime, msg.PathAttributes)

	var stop bool
	if args.f != nil {
		stop = args.f(dump)
	}

	args.iter++

	return stop
}

func (rib *LcRib) DumpMrt(peerid uint16, f WalkMrt, ts time.Time) {
	args := dumpWalkArgs{
		f:       f,
		peerid:  peerid,
		afi:     messages.AFI_IPV4,
		safi:    messages.SAFI_UNICAST,
		curtime: ts,
	}
	rib.Walk(args.dumpWalk, args.isv6)

	args.afi = messages.AFI_IPV6
	args.isv6 = true

	rib.Walk(args.dumpWalk, args.isv6)
}

func (rib *LcRib) chooseTableByType(ip net.IP) (*lctrie.Trie, *sync.RWMutex) {
	if ip.To4() != nil {
		return rib.PrefixTable, rib.SyncPrefixTable
	} else if ip.To16() != nil {
		return rib.Prefix6Table, rib.SyncPrefix6Table
	} else {
		return nil, nil
	}
}

type walkArgs struct {
	f    Walk
	isv6 bool
}

func (rib *LcRib) GetCounts(afisafi messages.AfiSafi) int {
	if afisafi.Afi == messages.AFI_IPV4 {
		return rib.Countv4
	} else if afisafi.Afi == messages.AFI_IPV6 {
		return rib.Countv6
	}
	return 0
}

func (args *walkArgs) walkFunc(b []byte, p byte, item interface{}) bool {
	prefix := ConvertBytesToPrefix(b, p, args.isv6)

	conv, ok := item.(*messages.BGPMessageUpdate)
	var stop bool
	if ok && args.f != nil {
		stop = args.f(prefix, conv)
	}
	return stop
}

func (rib *LcRib) Walk(f Walk, isv6 bool) {
	args := walkArgs{
		f:    f,
		isv6: isv6,
	}

	if !isv6 {
		rib.SyncPrefixTable.RLock()
		rib.PrefixTable.ExploreFromRoot(args.walkFunc)
		rib.SyncPrefixTable.RUnlock()
	} else {
		rib.SyncPrefix6Table.RLock()
		rib.Prefix6Table.ExploreFromRoot(args.walkFunc)
		rib.SyncPrefix6Table.RUnlock()
	}
}

func (rib *LcRib) chooseTableByTypePrefix(prefix net.IPNet) (*lctrie.Trie, *sync.RWMutex) {
	return rib.chooseTableByType(prefix.IP)
}

func (rib *LcRib) LookupPrefix(prefix net.IPNet, exact bool) (net.IPNet, *messages.BGPMessageUpdate) {
	table, sync := rib.chooseTableByTypePrefix(prefix)

	var pconv net.IPNet
	if table == nil || sync == nil {
		return pconv, nil
	}

	b, p := ConvertPrefixToBytes(prefix)

	var bb []byte
	var pp byte
	var i interface{}
	sync.RLock()

	var isv6 bool
	if prefix.IP.To4() == nil && prefix.IP.To16() != nil {
		isv6 = true
	}

	if !exact {
		bb, pp, i = table.Get(b, p)
		pconv = ConvertBytesToPrefix(bb, pp, isv6)
	} else {
		i = table.GetExact(b, p)
		pconv = prefix
	}
	sync.RUnlock()

	update, ok := i.(*messages.BGPMessageUpdate)
	if ok {
		return pconv, update
	}

	return pconv, nil
}
func (rib *LcRib) Lookup(ip net.IP) (net.IPNet, *messages.BGPMessageUpdate) {
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(32, 32)
	} else if ip.To16() != nil {
		mask = net.CIDRMask(128, 128)
	}
	prefix := net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	return rib.LookupPrefix(prefix, false)
}

func ConvertBytesToPrefix(b []byte, p byte, ipv6 bool) net.IPNet {
	var newip []byte
	var mask net.IPMask

	var size int

	if ipv6 {
		size = 16
	} else {
		size = 4
	}

	if p == 0 {
		mask = net.CIDRMask(8*len(b), size*8)
	} else {
		modb := b[len(b)-1]

		b[len(b)-1] = (modb >> (8 - p)) << (8 - p)
		mask = net.CIDRMask(8*(len(b)-1)+int(p), size*8)
	}

	if size-len(b) > 0 {
		newip = append(b, make([]byte, size-len(b))...)
	} else {
		newip = append(b)
	}

	return net.IPNet{IP: newip, Mask: mask}
}

func ConvertPrefixToBytes(prefix net.IPNet) ([]byte, byte) {
	var ipbytes []byte
	var bytescopy net.IP
	bytescopy = make([]byte, len(prefix.IP))
	copy(bytescopy, prefix.IP)
	if bytescopy.To4() != nil {
		ipbytes = bytescopy.To4()
	} else if prefix.IP.To16() != nil {
		ipbytes = bytescopy.To16()
	}
	if ipbytes != nil {
		s, _ := prefix.Mask.Size()
		if s == 0 {
			return []byte{}, 0
		}
		cut := s / 8
		if s%8 != 0 {
			cut += 1
		}
		ipbytes := ipbytes[0:cut]
		s %= 8
		return ipbytes, byte(s)
	}
	return nil, 0
}

func ConvertNLRIToBytes(nlri messages.NLRI) ([]byte, byte) {
	ipprefix, ok := nlri.(messages.NLRI_IPPrefix)
	if ok {
		return ConvertPrefixToBytes(ipprefix.Prefix)
	} else {
		return nil, 0
	}

}

func RemoveFromNLRI(nlri messages.NLRI, message *messages.BGPMessageUpdate) {
	newnlri := make([]messages.NLRI, 0)
	for i := range message.NLRI {
		if !nlri.Equals(message.NLRI[i]) {
			newnlri = append(newnlri, message.NLRI[i])
		}
	}
	if len(newnlri) != len(message.NLRI) {
		message.NLRI = newnlri
	}

	newnlri = make([]messages.NLRI, 0)
	for i := range message.PathAttributes {
		switch pa := message.PathAttributes[i].(type) {
		case messages.BGPAttribute_MP_REACH:
			for j := range pa.NLRI {
				if !nlri.Equals(pa.NLRI[j]) {
					newnlri = append(newnlri, pa.NLRI[j])
				}
			}
			if len(newnlri) != len(pa.NLRI) {
				pa.NLRI = newnlri
			}
		}
	}
}

func (rib *LcRib) addPrefix(nlri messages.NLRI, trie *lctrie.Trie, message *messages.BGPMessageUpdate, count *int) {
	b, l := ConvertNLRIToBytes(nlri)
	//fmt.Printf("Converted %v %v\n", b, l)
	if b != nil {

		val := trie.GetExact(b, byte(l%8))
		if val != nil {
			valupdate, ok := val.(*messages.BGPMessageUpdate)
			if ok && valupdate != message {
				RemoveFromNLRI(nlri, valupdate)
			}
		} else {
			(*count)++
		}
		trie.Insert(b, byte(l%8), message)
	}
}

func (rib *LcRib) delPrefix(nlri messages.NLRI, trie *lctrie.Trie, count *int) int {
	b, l := ConvertNLRIToBytes(nlri)
	//fmt.Printf("Converted %v %v\n", b, l)
	if b != nil {

		val := trie.GetExact(b, byte(l%8))
		if val != nil {
			valupdate, ok := val.(*messages.BGPMessageUpdate)
			if ok {
				RemoveFromNLRI(nlri, valupdate)
			}
			(*count)--
		}
		return trie.Remove(b, byte(l%8))
	}
	return 0
}

func (rib *LcRib) UpdateRib(message *messages.BGPMessageUpdate) {
	if message == nil {
		return
	}
	rib.SyncPrefixTable.Lock()
	for i := range message.NLRI {
		//fmt.Printf("Adding %v (%v/%v)\n", message.NLRI[i], i+1, len(message.NLRI))
		rib.addPrefix(message.NLRI[i], rib.PrefixTable, message, &rib.Countv4)
	}
	rib.SyncPrefixTable.Unlock()

	rib.SyncPrefixTable.Lock()
	for i := range message.WithdrawnRoutes {
		//fmt.Printf("Remove %v\n", message.WidthdrawnRoutes[i])
		rib.delPrefix(message.WithdrawnRoutes[i], rib.PrefixTable, &rib.Countv4)
	}
	message.WithdrawnRoutes = make([]messages.NLRI, 0)
	rib.SyncPrefixTable.Unlock()

	for i := range message.PathAttributes {
		switch pa := message.PathAttributes[i].(type) {
		case messages.BGPAttribute_MP_REACH:
			rib.SyncPrefix6Table.Lock()
			for j := range pa.NLRI {
				//fmt.Printf("Adding %v\n", pa.NLRI[j])
				rib.addPrefix(pa.NLRI[j], rib.Prefix6Table, message, &rib.Countv6)
			}
			rib.SyncPrefix6Table.Unlock()

		case messages.BGPAttribute_MP_UNREACH:
			rib.SyncPrefix6Table.Lock()
			for j := range pa.NLRI {
				//fmt.Printf("Remove %v\n", pa.NLRI[j])
				rib.delPrefix(pa.NLRI[j], rib.Prefix6Table, &rib.Countv6)
			}
			pa.NLRI = make([]messages.NLRI, 0)
			rib.SyncPrefix6Table.Unlock()
		}
	}

}
