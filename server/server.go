package fgbgp

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cloudflare/fgbgp/messages"
	"github.com/cloudflare/fgbgp/rib"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

const (
	STATE_IDLE = iota
	STATE_CONNECT
	STATE_ACTIVE
	STATE_OPENSENT
	STATE_OPENCONFIRM
	STATE_ESTABLISHED
)

type State struct {
	CurState     int
	OpenReceived bool
	Time         time.Time
}

type BGPEventHandler interface {
	NewNeighbor(*messages.BGPMessageOpen, *Neighbor) bool
	OpenSend(*messages.BGPMessageOpen, *Neighbor) bool
	DisconnectedNeighbor(*Neighbor)

	//KeepAlive(*Neighbor) (bool)
	Notification(*messages.BGPMessageNotification, *Neighbor) bool

	ProcessReceived(interface{}, *Neighbor) (bool, error)
	ProcessSend(interface{}, *Neighbor) (bool, error)

	//ProcessEvent(ev interface{}, *Neighbor)
}

type MPStruct struct {
	Afi  string
	Safi string
}

type AddPathStruct struct {
	Afi  string
	Safi string
	RxTx byte
}

type Neighbor struct {
	Addr  net.IP
	Port  int
	State *State

	Afi  uint16
	Safi byte

	Connected bool
	Reconnect bool

	/*
	   ConnectRetryCounter
	   ConnectRetryTimer
	   ConnectRetryTime
	   HoldTimer
	   HoldTime
	   KeepaliveTimer
	   KeepaliveTime
	*/

	tcpconn *net.TCPConn
	s       *Server
	qLife   chan bool
	qSender chan bool
	update  chan interface{}

	HandlerEvent  BGPEventHandler
	HandlerUpdate BGPUpdateHandler
	//HandlerRoute RouteHandler

	// Given by peer Open Message
	LastKeepAliveSent     time.Time
	PeerEnableKeepAlive   bool
	PeerHoldTime          time.Duration
	PeerMultiprotocolList []messages.BGPCapability_MP
	PeerAddPathList       []messages.AddPath
	PeerASN               uint32
	PeerRouteRefresh      bool
	Peer2Bytes            bool
	PeerIdentifier        net.IP

	// Local configuration sent in Open
	LocalLastKeepAliveRecv time.Time
	LocalEnableKeepAlive   bool
	LocalHoldTime          time.Duration
	Identifier             net.IP
	ASN                    uint32
	MultiprotocolList      []messages.BGPCapability_MP
	AddPathList            []messages.AddPath
	RouteRefresh           bool

	// Populated after open
	SendAddPath   []messages.AfiSafi
	DecodeAddPath []messages.AfiSafi

	// General configuration
	ReplicateASN       bool // Sends the same ASN as received
	Passive            bool
	RemoveOnDisconnect bool

	OutQueue chan messages.SerializableInterface

	Rib rib.Rib
}

type Manager struct {
	Neighbors    []*Neighbor
	neighborlock *sync.RWMutex

	Servers    []*Server
	serverlock *sync.RWMutex
	q          chan bool

	HandlerEvent  BGPEventHandler
	HandlerUpdate BGPUpdateHandler

	ASN          uint32
	Identifier   net.IP
	AddPath      bool
	HoldTime     int
	RouteRefresh bool

	MemPool *sync.Pool
}

type Server struct {
	Addr    net.IP
	Port    int
	Manager *Manager

	inconn *net.TCPListener
	laddr  *net.TCPAddr
}

func (n *Neighbor) RefreshAll() error {
	err := n.Refresh(messages.AfiSafi{Afi: messages.AFI_IPV4, Safi: messages.SAFI_UNICAST})
	if err != nil {
		return err
	}
	err = n.Refresh(messages.AfiSafi{Afi: messages.AFI_IPV6, Safi: messages.SAFI_UNICAST})
	return err
}

func (n *Neighbor) Refresh(afisafi messages.AfiSafi) error {
	if n.PeerRouteRefresh {
		log.Infof("%v: Refreshing routes for %v", n.String(), afisafi.String())
		rr := messages.BGPMessageRouteRefresh{AfiSafi: afisafi}
		n.OutQueue <- rr
		return nil
	} else {
		// Should reset session?
		return errors.New(fmt.Sprintf("%v: No route refresh capability.", n.String()))
	}
}

func (n *Neighbor) GetLocalAddress() (net.IP, int) {
	//return n.s.Addr, n.s.Port
	laddr := n.tcpconn.LocalAddr()
	if laddr != nil {
		tcpaddr, _ := net.ResolveTCPAddr(laddr.Network(), laddr.String())
		if tcpaddr != nil {
			return tcpaddr.IP, tcpaddr.Port
		}
	}
	return nil, 0
}

func (n *Neighbor) Connect() error {
	log.Infof("%v: Connecting", n.String())
	tcpaddr := net.TCPAddr{
		IP:   n.Addr,
		Port: n.Port,
	}
	var errd error
	n.tcpconn, errd = net.DialTCP("tcp", nil, &tcpaddr)
	if errd != nil {
		return errd
	}
	n.Connected = true
	return nil
}

func (n *Neighbor) Disconnect() {
	log.Infof("%v: Disconnected", n.String())
	wasConnected := n.Connected
	n.Connected = false
	n.State.OpenReceived = false
	n.tcpconn.Close()
	n.UpdateState(STATE_IDLE)

	if n.HandlerEvent != nil && wasConnected == true {
		n.HandlerEvent.DisconnectedNeighbor(n)
	}

	if n.RemoveOnDisconnect && n.s != nil && n.s.Manager != nil {
		log.Infof("%v: Removing from manager", n.String())
		select {
			case n.qLife <- true:
			default:
		}
		select {
			case n.qSender <- true:
			default:
		}

		n.s.Manager.RemoveNeighbor(n)
	}
}

func (n *Neighbor) String() string {
	return fmt.Sprintf("%v:%v/%v", n.Addr.String(), n.Port, n.PeerASN)
}

func (n *Neighbor) SendRoute(
	afisafi messages.AfiSafi,
	nlri []messages.NLRI,
	withdraw []messages.NLRI,
	nextHop net.IP,
	communities []uint32,
	aspath []uint32,
	med uint32,
	locpref uint32) {
	update := n.CraftUpdate(afisafi, nlri, withdraw, nextHop, communities, aspath, med, locpref)
	n.OutQueue <- update
}

func (n *Neighbor) CraftUpdate(
	afisafi messages.AfiSafi,
	nlri []messages.NLRI,
	withdraw []messages.NLRI,
	nextHop net.IP,
	communities []uint32,
	aspath []uint32,
	med uint32,
	locpref uint32) *messages.BGPMessageUpdate {
	update := &messages.BGPMessageUpdate{}

	return update
}

func (n *Neighbor) UpdateState(newstate int) {
	n.State.CurState = newstate
	n.State.Time = time.Now().UTC()
}

func CompareAddPath(local []messages.AddPath, remote []messages.AddPath) ([]messages.AfiSafi, []messages.AfiSafi) {
	recv := make([]messages.AfiSafi, 0)
	send := make([]messages.AfiSafi, 0)
	for i := range local {
		for j := range remote {
			if local[i].EqualsAfiSafi(remote[j]) {
				if (local[i].TxRx | remote[j].TxRx) == 3 {
					if remote[i].TxRx&2 != 0 && local[i].TxRx&1 != 0 {
						recv = append(recv, messages.AfiSafi{local[i].Afi, local[i].Safi})
					}
					if remote[i].TxRx&1 != 0 && local[i].TxRx&2 != 0 {
						send = append(send, messages.AfiSafi{local[i].Afi, local[i].Safi})
					}
				}
				break
			}
		}
	}
	return send, recv
}

func (n *Neighbor) UpdateFromOpen(pkt *messages.BGPMessageOpen) {
	n.PeerASN = uint32(pkt.ASN)
	n.PeerIdentifier = pkt.Identifier
	n.Peer2Bytes = true
	for i := range pkt.Parameters {
		if pkt.Parameters[i].Type == messages.PARAMETER_CAPA {
			capas := pkt.Parameters[i].Data.(messages.BGPCapabilities)
			for c := range capas.BGPCapabilities {
				switch ct := capas.BGPCapabilities[c].(type) {
				case messages.BGPCapability_MP:
					n.PeerMultiprotocolList = append(n.MultiprotocolList, ct)
				case messages.BGPCapability_ADDPATH:
					n.PeerAddPathList = ct.AddPathList
					n.SendAddPath, n.DecodeAddPath = CompareAddPath(n.AddPathList, n.PeerAddPathList)
					log.Debugf("%v: Add-path: Send on %v Afi-Safi / Receive on %v Afi-Safi", n.String(), len(n.SendAddPath), len(n.DecodeAddPath))
				case messages.BGPCapability_ASN:
					n.Peer2Bytes = false
					n.PeerASN = ct.ASN
				case messages.BGPCapability_ROUTEREFRESH:
					n.PeerRouteRefresh = true
				}
			}
		}
	}
}

func (n *Neighbor) EvolveState(pkt interface{}) {
	switch pktt := pkt.(type) {
	case *messages.BGPMessageOpen:
		log.Info(pktt.String())

		if pktt.HoldTime != 0 {
			n.PeerHoldTime = time.Duration(time.Duration(int(pktt.HoldTime)) * time.Second)
			n.PeerEnableKeepAlive = true
		}

		if n.ReplicateASN {
			n.ASN = n.PeerASN
		}

		n.UpdateFromOpen(pktt)
		n.State.OpenReceived = true

		if n.HandlerEvent != nil {
			ret := n.HandlerEvent.NewNeighbor(pktt, n)
			if !ret {
				log.Infof("%v: handler forced disconnect.", n.String())
				n.Disconnect()
			}
		}

	case *messages.BGPMessageKeepAlive:
		if n.State.CurState == STATE_OPENCONFIRM {
			log.Debugf("%v: OpenConfirm -> Established", n.String())
			n.UpdateState(STATE_ESTABLISHED)
		}
	case *messages.BGPMessageNotification:
		log.Errorf("%v: Received notification: %v", n.String(), pktt)
		if n.HandlerEvent != nil {
			n.HandlerEvent.Notification(pktt, n)
		}
		n.Disconnect()
	}

	if pkt != nil {
		n.LocalLastKeepAliveRecv = time.Now().UTC()
	}

	switch n.State.CurState {
	case STATE_IDLE:
		// check timers
		if !n.Passive {
			// Change nil for when binding to specific IP or IP+port
			err := n.Connect()
			if err == nil {
				log.Debugf("%v: Idle -> Active", n.String())
				n.UpdateState(STATE_ACTIVE)
			} else {
				log.Errorf("%v: Error connecting: %v", n.String(), err)
			}
		}
	case STATE_ACTIVE:
		if !n.Passive || n.State.OpenReceived {
			var ht uint16
			if n.LocalEnableKeepAlive {
				ht = uint16(n.LocalHoldTime / time.Second)
			}

			open := messages.CraftOpenMessage(n.ASN, ht, n.Identifier.To4(), n.MultiprotocolList, n.AddPathList, n.RouteRefresh)
			log.Debugf("%v: Active -> OpenSent", n.String())
			n.OutQueue <- open

			ka := messages.CraftKeepAliveMessage()
			n.OutQueue <- ka

			n.UpdateState(STATE_OPENSENT)
		}

	case STATE_OPENSENT:
		if n.State.OpenReceived {
			log.Debugf("%v: OpenSent -> OpenConfirm", n.String())
			n.UpdateState(STATE_OPENCONFIRM)
		}

	case STATE_ESTABLISHED:
		// Check timers send
		if n.PeerEnableKeepAlive && n.LastKeepAliveSent.Add((n.PeerHoldTime/time.Second)/3).Before(time.Now().UTC()) {
			ka := messages.BGPMessageKeepAlive{}
			n.OutQueue <- ka
			log.Debugf("Established / KeepAlive")
			n.LastKeepAliveSent = time.Now().UTC()
		}
	case STATE_OPENCONFIRM:
		// Check timers send
		if n.PeerEnableKeepAlive && n.LastKeepAliveSent.Add((n.PeerHoldTime/time.Second)/3).Before(time.Now().UTC()) {
			ka := messages.BGPMessageKeepAlive{}
			n.OutQueue <- ka
			//log.Debugf("OpenConfirm / KeepAlive")
			n.LastKeepAliveSent = time.Now().UTC()
		}
	}

	if n.State.CurState != STATE_IDLE && n.State.CurState != STATE_ACTIVE && n.LocalEnableKeepAlive && n.LocalLastKeepAliveRecv.Add(n.LocalHoldTime).Before(time.Now().UTC()) {
		// Craft error hold time message
		log.Errorf("%v: no keep-alive received. Disconnecting.", n.String())
		n.Disconnect()
	}

}

func (n *Neighbor) NeighborLifeRoutine() {
	for {
		select {
		case msg := <-n.update:
			n.EvolveState(msg)
		case <-time.After(time.Duration(1 * time.Second)):
			n.EvolveState(nil)
		case <-n.qLife:
			log.Infof("%v: NeighborLifeRoutine stopped", n.String())
			return
		}
	}
}

func (n *Neighbor) SenderRoutine() {
	for {
		select {
		case msg := <-n.OutQueue:
			buf := bytes.NewBuffer([]byte{})
			msg.Write(buf)
			_, err := n.tcpconn.Write(buf.Bytes())

			if err != nil {
				log.Errorf("%v: error sender %v", n.String(), err)
				n.Disconnect()
			}
		case <-n.qSender:
			log.Infof("%v: SenderRoutine stopped", n.String())
			return
		}
	}
}

func ReadFromSocket(tcpconn *net.TCPConn, msg []byte) error {
	var err error
	var i int
	var read int
	for read < len(msg) && err == nil {
		tmpmsg := make([]byte, len(msg)-read)
		i, err = tcpconn.Read(tmpmsg)
		/*if i < len(msg) {
		    log.Debugf("Read following from %v/%v: %v/%v/%v length", tcpconn.RemoteAddr(), tcpconn.LocalAddr(), read, i, len(msg))
		}*/
		copy(msg[read:read+i], tmpmsg[:])
		read += i
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *Neighbor) NeighborReceiveRoutine() {
	for {
		if n.Connected {
			msg := make([]byte, 19)
			err := ReadFromSocket(n.tcpconn, msg)

			var toread uint16
			var bgptype byte
			if err == nil {
				bgptype, toread, err = messages.ParsePacketHeader(msg)
				//log.Debugf("Received from %v/%v: %v bytes", n.tcpconn.RemoteAddr(), n.tcpconn.LocalAddr(), toread)

				if toread > 0 {
					msg = make([]byte, toread)
					err = ReadFromSocket(n.tcpconn, msg)
				}
			}

			if err != nil {
				// Socket might not be clean enough so even if the connection is redone, this error can be raised
				log.Errorf("NeighborReceiveRoutine: %v", err)
				n.Disconnect()
				continue
			}

			if bgptype != messages.MESSAGE_NOTIFICATION {
				n.LocalLastKeepAliveRecv = time.Now().UTC()
			}

			if bgptype != messages.MESSAGE_UPDATE {
				var p interface{}
				p, err = messages.ParsePacket(bgptype, msg)
				if err != nil {
					log.Error(err)
					n.Disconnect()
					continue
				}

				if n.HandlerEvent != nil {
					var continueskip bool
					continueskip, err = n.HandlerEvent.ProcessReceived(p, n)
					if !continueskip || err != nil {
						continue
					}
				}

				select {
				case n.update <- p:
				// unsure about the non-blocking function->we may loose a packet
				// Better a queue and this as a refresh indication (for a loop inside the EvolveState for all the unprocessed packets)
				default:
				}

			} else {
				if n.HandlerUpdate != nil {
					n.HandlerUpdate.ProcessUpdate(msg, n)
				}
			}

			/*switch pkt := p.(type) {
			  case *BGPMessageUpdate:
			      // save
			      log.Debugf("UPDATE %v", pkt)
			  default:
			      select {
			      case n.update<-p:
			      // unsure about the non-blocking function->we may loose a packet
			      // Better a queue and this as a refresh indication (for a loop inside the EvolveState for all the unprocessed packets)
			      default:
			      }
			  }*/

		} else {
			select {
			case <-time.After(time.Duration(1 * time.Millisecond)):
				if !n.Connected {
					//log.Errorf("%v: Neighbor not connected", n.String())
					if !n.Reconnect {
						//n.Remove()
						log.Infof("%v: NeighborReceiveRoutine stopped", n.String())
						return
					}
				}
			}
		}
	}
}

func (n *Neighbor) Start() {
	go n.NeighborReceiveRoutine()
	go n.NeighborLifeRoutine()
	go n.SenderRoutine()
}

func (s *Server) ProcessIncomingRequest(tcpconn *net.TCPConn) {
	log.Debugf("Creating new neighbor from incoming connection: %v", tcpconn.RemoteAddr().String())
	n := NewNeighborFromConn(tcpconn, s.Manager.Identifier, s.Manager.ASN, s.Manager.AddPath, s.Manager.HoldTime, s.Manager.RouteRefresh)
	n.HandlerEvent = s.Manager.HandlerEvent
	n.HandlerUpdate = s.Manager.HandlerUpdate
	n.Connected = true
	n.RemoveOnDisconnect = true
	n.s = s
	n.Start()
	s.Manager.AddNeighbor(n)
}

func (s *Server) ServerRoutine() {
	var errcreate error
	s.inconn, errcreate = net.ListenTCP("tcp", s.laddr)
	if errcreate != nil {
		log.Fatal(errcreate)
	}

	for {
		tcpconn, err := s.inconn.AcceptTCP()
		if err != nil {
			log.Error(err)
		} else {
			go s.ProcessIncomingRequest(tcpconn)
		}
	}
}

func NewNeighborFromConn(tcpconn *net.TCPConn, identifier net.IP, asn uint32, addpath bool, holdtime int, routerefresh bool) *Neighbor {
	addr := tcpconn.RemoteAddr()
	tcpaddr, _ := net.ResolveTCPAddr("tcp", addr.String())
	n := NewNeighbor(tcpaddr.IP, tcpaddr.Port, identifier, asn, addpath, holdtime, routerefresh)
	n.Passive = true
	n.tcpconn = tcpconn
	n.UpdateState(STATE_ACTIVE)
	n.Reconnect = false
	return n
}

func NewNeighbor(addr net.IP, port int, identifier net.IP, asn uint32, addpath bool, holdtime int, routerefresh bool) *Neighbor {
	n := &Neighbor{
		Addr:       addr,
		Port:       port,
		State:      &State{},
		qLife:      make(chan bool),
		qSender:    make(chan bool),
		update:     make(chan interface{}, 5),
		Identifier: identifier,
		ASN:        asn,
		MultiprotocolList: []messages.BGPCapability_MP{
			messages.BGPCapability_MP{messages.AFI_IPV4, messages.SAFI_UNICAST},
			messages.BGPCapability_MP{messages.AFI_IPV6, messages.SAFI_UNICAST}},
		PeerMultiprotocolList: make([]messages.BGPCapability_MP, 0),
		PeerAddPathList:       make([]messages.AddPath, 0),
		OutQueue:              make(chan messages.SerializableInterface, 1000),
		Rib:                   rib.NewLcRib(),
		Reconnect:             true,
		RouteRefresh:          routerefresh,
	}

	if holdtime >= 3 {
		n.LocalHoldTime = time.Duration(time.Duration(holdtime) * time.Second)
		n.LocalEnableKeepAlive = true
	}

	if addpath {
		n.AddPathList = []messages.AddPath{
			messages.AddPath{messages.AFI_IPV4, messages.SAFI_UNICAST, 3},
			messages.AddPath{messages.AFI_IPV6, messages.SAFI_UNICAST, 3}}
	}

	n.Afi = messages.AFI_IPV4
	n.Safi = messages.SAFI_UNICAST
	if addr.To4() == nil {
		n.Afi = messages.AFI_IPV6
	}

	return n
}

func NewManager(asn uint32, identifier net.IP, addpath bool, routerefresh bool) *Manager {
	m := &Manager{
		Neighbors:    make([]*Neighbor, 0),
		neighborlock: &sync.RWMutex{},

		Servers:    make([]*Server, 0),
		serverlock: &sync.RWMutex{},

		ASN:        asn,
		Identifier: identifier,

		AddPath:  addpath,
		HoldTime: 90,

		RouteRefresh: routerefresh,

		q: make(chan bool),

		MemPool: &sync.Pool{},
	}
	return m
}

func (m *Manager) RemoveNeighbor(n *Neighbor) {
	log.Debugf("Removing neighbor %v", n.String())
	newlist := make([]*Neighbor, 0)
	m.neighborlock.Lock()
	for i := range m.Neighbors {
		if m.Neighbors[i] != n {
			newlist = append(newlist, m.Neighbors[i])
		} else {
			m.MemPool.Put(n)
			log.Debugf("Putting %v into sync pool", n)
		}
	}

	m.Neighbors = newlist
	m.neighborlock.Unlock()
}

func (m *Manager) AddNeighbor(n *Neighbor) {
	m.neighborlock.Lock()
	m.Neighbors = append(m.Neighbors, n)
	m.neighborlock.Unlock()
}

func (m *Manager) NewServer(addr string) error {
	tcpaddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	s := &Server{
		Addr:    tcpaddr.IP,
		Port:    tcpaddr.Port,
		laddr:   tcpaddr,
		Manager: m,
	}
	m.serverlock.Lock()
	m.Servers = append(m.Servers, s)
	m.serverlock.Unlock()
	return nil
}

func (m *Manager) GetNeighbors() []*Neighbor {
	m.neighborlock.RLock()
	neighlist := make([]*Neighbor, len(m.Neighbors))
	for i := range m.Neighbors {
		neighlist[i] = m.Neighbors[i]
	}
	m.neighborlock.RUnlock()
	return neighlist
}

func (m *Manager) ApplyUpdateHandlerToNeighbors() {
	uh := m.HandlerUpdate
	m.neighborlock.RLock()
	for i := range m.Neighbors {
		m.Neighbors[i].HandlerUpdate = uh
	}
	m.neighborlock.RUnlock()
}

func (m *Manager) SetEventHandler(eh BGPEventHandler) {
	m.HandlerEvent = eh
	m.neighborlock.RLock()
	for i := range m.Neighbors {
		m.Neighbors[i].HandlerEvent = eh
	}
	m.neighborlock.RUnlock()
}

func (m *Manager) UseDefaultUpdateHandler(workers int) {
	if m.HandlerUpdate != nil {
		m.HandlerUpdate.Close()
	}

	uh := m.CreateDefaultUpdateHandler(workers)

	m.HandlerUpdate = uh
	m.ApplyUpdateHandlerToNeighbors()
}

// Set a more defined update handler (after processing and adding it to the Neighbor RIB).
// Must be using default event handler
func (m *Manager) SetUpdateEventHandler(eh BGPUpdateEventHandler) error {
	if m.HandlerUpdate != nil {
		assert, ok := m.HandlerUpdate.(*DefaultBGPUpdateHandler)
		if !ok {
			return errors.New("SetUpdateEventHandler: HandlerUpdate must be a Default Handler")
		} else {
			assert.SetUpdateEventHandler(eh)
			return nil
		}
	} else {
		return errors.New("SetUpdateEventHandler: HandlerUpdate is nil, please instanciate to Default Handler")
	}
}

func (m *Manager) Start() {
	m.StartServers()
	m.neighborlock.RLock()
	for i := range m.Neighbors {
		m.Neighbors[i].Start()
	}
	m.neighborlock.RUnlock()
	for {
		select {
		case <-m.q:
			// Cut connections
			break
			break
		}
	}
}
func (m *Manager) Stop() {
	m.q <- true
}

func (m *Manager) StartServers() {
	m.serverlock.RLock()
	for i := range m.Servers {
		m.Servers[i].Start()
	}
	m.serverlock.RUnlock()
}

func (s *Server) Start() {
	go s.ServerRoutine()
}
