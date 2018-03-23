package rib

import (
	"github.com/cloudflare/fgbgp/messages"
	"net"
	"time"
)

type Rib interface {
	Lookup(ip net.IP) (net.IPNet, *messages.BGPMessageUpdate)
	LookupPrefix(prefix net.IPNet, exact bool) (net.IPNet, *messages.BGPMessageUpdate)

	UpdateRib(*messages.BGPMessageUpdate)

	GetCounts(messages.AfiSafi) int

	DumpMrt(peerid uint16, f WalkMrt, ts time.Time)
	Walk(f Walk, isv6 bool)
}

func NewRib(typeRib int) Rib {
	return NewLcRib()
}
