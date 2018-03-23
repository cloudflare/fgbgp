# FGBGP

This is a BGP library in Go.

## Features

* Decode/encode BGP messages
* Maintain a connexion with peers
* RIB data structure (add/remove IPv4/IPv6)
* Event-based API
* Encode/decode MRT format

## Why use this library?

It was developped to have a flexible BGP server running on a cluster with
load-balanced IPs and ready for scale.
A full-table will use around 300MB of RAM.

This is not a fully integrated BGP daemon: it does not filter routes or
automatically send BGP updates on the routes learned.

The behavior has to be implemented using the event-based API:
* Peer status change
* Update received

This library can also be used for standalone BGP Messages decoding,
reading MRT files or storing updates into a RIB and perform lookups.

### Supported BGP features

* Add-path (decode/encode only, not storing into the RIB)
* Route-refresh
* Basic BGP attributes (Origin, MED...)
* Aggregator

### Supported MRT features

* TABLEDUMPV2
* MRT update
* Status

## Example

```
import (
    "fmt"
    server "fgbgp/server"
)

type Collector struct {

}

func (col *Collector) Notification(msg *messages.BGPMessageNotification, n *server.Neighbor) (bool) {
    return true
}

func (col *Collector) ProcessReceived(v interface{}, n *server.Neighbor) (bool, error) {
    return true, nil
}

func (col *Collector) ProcessSend(v interface{}, n *server.Neighbor) (bool, error) {
    return true, nil
}

func (col *Collector) ProcessUpdateEvent(e *messages.BGPMessageUpdate, n *server.Neighbor) (add bool) {

}

func main() {
    m := server.NewManager(65001, net.ParseIP("10.0.0.1"), false, false)
    m.UseDefaultUpdateHandler(10)
    col := &Collector{}
    m.SetEventHandler(&col)
    m.SetUpdateEventHandler(&col)
    err := m.NewServer(*BgpAddr)
    if err != nil {
        log.Fatal(err)
    } 
}
```
