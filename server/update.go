package fgbgp

import (
	"errors"
	"fmt"
	"github.com/cloudflare/fgbgp/messages"
	log "github.com/sirupsen/logrus"
	"sync/atomic"
)

type BGPUpdateHandler interface {
	ProcessUpdate([]byte, *Neighbor)
	Close()
}

type BGPUpdateEventHandler interface {
	ProcessUpdateEvent(*messages.BGPMessageUpdate, *Neighbor) (add bool)
}

type DefaultBGPUpdateHandler struct {
	Manager    *Manager
	WorkerPool *Pool

	UpdateMsgCount uint64

	RibPerNeighbor map[int]interface{}

	UpdateEventHandler BGPUpdateEventHandler
}

type DefaultMessageUpdate struct {
	Msg      []byte
	Neighbor *Neighbor
}

func (n *Neighbor) UpdateRib(m *messages.BGPMessageUpdate) {
	n.Rib.UpdateRib(m)
}

func (uh *DefaultBGPUpdateHandler) ProcessUpdate(msg []byte, n *Neighbor) {
	msgdispatch := &DefaultMessageUpdate{
		Msg:      msg,
		Neighbor: n,
	}

	uh.WorkerPool.Dispatch(msgdispatch)
}

func (uh *DefaultBGPUpdateHandler) Close() {
	uh.WorkerPool.Stop()
}

func (uh *DefaultBGPUpdateHandler) Process(id int, msg interface{}) error {
	atomic.AddUint64(&(uh.UpdateMsgCount), 1)

	msgt := msg.(*DefaultMessageUpdate)
	v, err := messages.ParseUpdate(msgt.Msg, msgt.Neighbor.DecodeAddPath, msgt.Neighbor.Peer2Bytes)

	if v == nil {
		return errors.New(fmt.Sprintf("Null update: %v", err))
	}

	add := true
	if uh.UpdateEventHandler != nil {
		add = uh.UpdateEventHandler.ProcessUpdateEvent(v, msgt.Neighbor)
	}

	if add {
		msgt.Neighbor.UpdateRib(v)
	}

	if err != nil {
		return err
	}

	return nil
}

func (uh *DefaultBGPUpdateHandler) Error(id int, msg interface{}, err error) {
	log.Errorf("DefaultBGPUpdateHandler: %v", err)
}

func (uh *DefaultBGPUpdateHandler) SetUpdateEventHandler(eh BGPUpdateEventHandler) {
	uh.UpdateEventHandler = eh
}

func (m *Manager) CreateDefaultUpdateHandler(workers int) *DefaultBGPUpdateHandler {
	uh := &DefaultBGPUpdateHandler{
		Manager: m,
	}

	pool := CreatePool(workers, uh)
	uh.WorkerPool = pool

	pool.Start()

	return uh
}

/*
func GenerateUpdate(info *rib.BGPPathInformation, addpathlist []messages.AfiSafi) *messages.BGPMessageUpdate {
    afisafi := messages.AfiSafi{
        Afi: messages.AFI_IPV4,
        Safi: messages.SAFI_UNICAST,
    }

    info.SyncNLRI.RLock()
    nlri := make([]messages.NLRI, len(info.NLRI))
    copy(nlri, info.NLRI)
    info.SyncNLRI.RUnlock()
    if len(info.NLRI) == 0 {
        return nil
    } else {
        ip := nlri[0]
        if ip.Prefix.IP.To4() == nil {
            afisafi = messages.AfiSafi{
                Afi: messages.AFI_IPV6,
                Safi: messages.SAFI_UNICAST,
            }
        }
    }

    addpath := messages.InAfiSafi(afisafi.Afi, afisafi.Safi, addpathlist)

    m := &messages.BGPMessageUpdate{}

    pa := []messages.BGPAttributeIf{
            messages.BGPAttribute_ORIGIN{
                Origin: info.Origin,
            },
        }

    if len(info.ASPath) > 0 {
        pa = append(pa, messages.BGPAttribute_ASPATH{
                SType: 2,
                ASPath: info.ASPath,})
    }
    if len(info.Communities) > 0 {
        pa = append(pa, messages.BGPAttribute_COMMUNITIES{
                Communities: info.Communities,})
    }
    if info.Med != 0 {
        pa = append(pa, messages.BGPAttribute_MED{
                Med: info.Med,})
    }
    if info.LocPref != 0 {
        pa = append(pa, messages.BGPAttribute_LOCPREF{
                LocPref: info.LocPref,})
    }

    if afisafi.Afi == messages.AFI_IPV4 {
        if info.NextHop != nil {
            pa = append(pa, messages.BGPAttribute_NEXTHOP{
                NextHop: info.NextHop.To4(),})
        }
        m.NLRI = nlri

        if addpath {
            m.EnableAddPath = true
        }

    } else if afisafi.Afi == messages.AFI_IPV6 {
        attr := messages.BGPAttribute_MP_REACH{
                    Afi: messages.AFI_IPV6,
                    Safi: messages.SAFI_UNICAST,
                    NextHop: info.NextHop,
                    NLRI: nlri,
                }
        if addpath {
            attr.EnableAddPath = true
        }
        pa = append(pa, attr)
    }

    m.PathAttributes = pa
    return m
}
*/
