package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
)

type BGPCapability_MP struct {
	Afi  uint16
	Safi byte
}

type BGPCapability_ASN struct {
	ASN uint32
}

type AddPath struct {
	Afi  uint16
	Safi byte
	TxRx byte
}

type BGPCapability_ROUTEREFRESH struct {
}

type BGPCapability_ADDPATH struct {
	AddPathList []AddPath
}

type BGPCapability struct {
	Type byte
	Data []byte
}

type BGPCapabilityIf SerializableInterface

type BGPCapabilities struct {
	BGPCapabilities []BGPCapabilityIf
}

type BGPParameterIf SerializableInterface

type BGPParameter struct {
	Type byte
	Data BGPParameterIf
}

type BGPMessageOpen struct {
	BGPMessageHead
	Version    byte
	ASN        uint16
	HoldTime   uint16
	Identifier []byte
	Parameters []BGPParameter
}

func (m BGPParameter) String() string {
	str := "Parameter (%v):"
	str += m.Data.String()
	return fmt.Sprintf(str, m.Type)
}

func (m BGPCapability) String() string {
	str := "Capability: %v (%v): %v"
	return fmt.Sprintf(str, CapaDescr[int(m.Type)], m.Type, m.Data)
}

func (c BGPCapability_ROUTEREFRESH) String() string {
	return "Capability Route-Refresh"
}

func (c BGPCapability_MP) String() string {
	return fmt.Sprintf("Capability Multiprotocol: %v-%v (%v) (%v)", AfiToStr[c.Afi], SafiToStr[c.Safi], c.Afi, c.Safi)
}

func (c BGPCapability_ADDPATH) String() string {
	var addpathstr string
	for i := range c.AddPathList {
		addpathstr += c.AddPathList[i].String() + ", "
	}
	return fmt.Sprintf("Capability Add-Path: [ %v]", addpathstr)
}

func (c BGPCapability_ASN) String() string {
	return fmt.Sprintf("Capability ASN: %v", c.ASN)
}

func (c BGPCapabilities) String() string {
	var str string
	for i := range c.BGPCapabilities {
		if c.BGPCapabilities[i] != nil {
			str += c.BGPCapabilities[i].String() + ", "
		}
	}
	return str
}

func (m *BGPMessageOpen) String() string {
	str := "BGP Open: Version: %v / ASN: %v / HoldTime: %v / Identifier: %v / Parameters (%v): [ "
	ip := net.IP(m.Identifier)
	str = fmt.Sprintf(str, m.Version, m.ASN, m.HoldTime, ip.String(), len(m.Parameters))
	for i := range m.Parameters {
		str += m.Parameters[i].String()
	}
	str += "]"
	return str
}

func (m BGPCapabilities) Len() int {
	var sum int
	for c := range m.BGPCapabilities {
		sum += m.BGPCapabilities[c].Len()
	}
	return sum
}

func (c BGPCapabilities) Write(bw io.Writer) {
	for i := range c.BGPCapabilities {
		c.BGPCapabilities[i].Write(bw)
	}
}

func (m BGPCapability_ROUTEREFRESH) Len() int {
	return 2
}

func (m BGPCapability_ROUTEREFRESH) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, byte(CAPA_RR))
	binary.Write(bw, binary.BigEndian, byte(0))
}

func (m BGPCapability_MP) Len() int {
	return 6
}

func (m BGPCapability_MP) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, byte(CAPA_MP))
	binary.Write(bw, binary.BigEndian, byte(4))

	binary.Write(bw, binary.BigEndian, m.Afi)
	binary.Write(bw, binary.BigEndian, byte(0))
	binary.Write(bw, binary.BigEndian, m.Safi)
}

func (m BGPCapability_ASN) Len() int {
	return 6
}

func (m BGPCapability_ASN) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, byte(CAPA_ASN))
	binary.Write(bw, binary.BigEndian, byte(4))

	binary.Write(bw, binary.BigEndian, m.ASN)
}

func (p AddPath) Len() int {
	return 4
}

func (p AddPath) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, p.Afi)
	binary.Write(bw, binary.BigEndian, p.Safi)
	binary.Write(bw, binary.BigEndian, p.TxRx)
}

func (m BGPCapability_ADDPATH) Len() int {
	var sum int
	for c := range m.AddPathList {
		sum += m.AddPathList[c].Len()
	}
	return sum
}

func (m BGPCapability_ADDPATH) Write(bw io.Writer) {
	for c := range m.AddPathList {
		m.AddPathList[c].Write(bw)
	}
}

func (m BGPCapability) Len() int {
	return 1 + 1 + len(m.Data)
}

func (m BGPCapability) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, m.Type)
	binary.Write(bw, binary.BigEndian, byte(len(m.Data)))
	binary.Write(bw, binary.BigEndian, m.Data)
}

func (m BGPParameter) Len() int {
	return 1 + 1 + m.Data.Len()
}

func (m BGPParameter) Write(bw io.Writer) {
	binary.Write(bw, binary.BigEndian, m.Type)
	binary.Write(bw, binary.BigEndian, byte(m.Data.Len()))
	m.Data.Write(bw)
}

func (m BGPMessageOpen) LenParams() int {
	sum := 0
	for i := range m.Parameters {
		sum += m.Parameters[i].Len()
	}
	return sum
}

func (m BGPMessageOpen) LenContent() int {
	return 10 + m.LenParams()
}

func (m BGPMessageOpen) Len() int {
	return GetBGPHeaderLen() + m.LenContent()
}

func (m BGPMessageOpen) Write(bw io.Writer) {
	WriteBGPHeader(MESSAGE_OPEN, uint16(m.LenContent()), bw)
	binary.Write(bw, binary.BigEndian, m.Version)
	binary.Write(bw, binary.BigEndian, m.ASN)
	binary.Write(bw, binary.BigEndian, m.HoldTime)
	binary.Write(bw, binary.BigEndian, m.Identifier[0:4])
	binary.Write(bw, binary.BigEndian, byte(m.LenParams()))
	for i := range m.Parameters {
		m.Parameters[i].Write(bw)
	}
}

func (c BGPCapability) ParseCapability() BGPCapabilityIf {
	buf := bytes.NewBuffer(c.Data)
	var ret BGPCapabilityIf
	switch c.Type {
	case CAPA_MP:
		mpstruct := BGPCapability_MP{}
		binary.Read(buf, binary.BigEndian, &mpstruct.Afi)
		buf.ReadByte()
		binary.Read(buf, binary.BigEndian, &mpstruct.Safi)
		ret = mpstruct
	case CAPA_ADDPATH:
		apstruct := BGPCapability_ADDPATH{
			AddPathList: make([]AddPath, len(c.Data)/4),
		}
		for i := 0; i < len(c.Data)/4; i++ {
			binary.Read(buf, binary.BigEndian, &(apstruct.AddPathList[i].Afi))
			binary.Read(buf, binary.BigEndian, &(apstruct.AddPathList[i].Safi))
			binary.Read(buf, binary.BigEndian, &(apstruct.AddPathList[i].TxRx))
		}

		ret = apstruct
	case CAPA_ASN:
		asnstruct := BGPCapability_ASN{}
		binary.Read(buf, binary.BigEndian, &asnstruct.ASN)
		ret = asnstruct
	case CAPA_RR:
		ret = BGPCapability_ROUTEREFRESH{}
	default:
		unknownstruct := BGPCapability{}
		unknownstruct.Type = c.Type
		unknownstruct.Data = c.Data
		ret = unknownstruct
	}
	return ret
}

func ParseOpen(b []byte) (*BGPMessageOpen, error) {
	m := BGPMessageOpen{}

	if len(b) < 10 {
		return nil, errors.New(fmt.Sprintf("ParseOpen: wrong open size: %v < 10", len(b)))
	}
	version := b[0]
	asn := uint16(b[1])<<8 | uint16(b[2])
	holdtime := uint16(b[3])<<8 | uint16(b[4])

	if holdtime > 0 && holdtime < 3 {
		log.Warnf("ParseOpen: BGP open hold time must be zero or at least 3. Got %v.", holdtime)
	}

	identifier := b[5:9]
	optparamlen := int(b[9])

	m.Version = version
	m.HoldTime = holdtime
	m.Identifier = identifier
	m.ASN = asn
	m.Parameters = make([]BGPParameter, 0)

	if len(b)-10 != optparamlen {
		return nil, errors.New(fmt.Sprintf("ParseOpen: wrong open size for optional parameters: %v != %v", len(b)-10, optparamlen))
	}

	if optparamlen > 0 && len(b)-10 >= 2 {
		i := 10
		for i < len(b)-1 {
			parmtype := b[i]
			parmlength := int(b[i+1])

			if i+1+parmlength > len(b) {
				return nil, errors.New(fmt.Sprintf("ParseOpen: wrong parameter length: %v > %v", i+1+parmlength, len(b)))
			}

			i += 2
			bgpparameter := BGPParameter{
				Type: parmtype,
			}

			var parameterdata BGPCapabilityIf
			baseparam := i

			switch parmtype {
			case PARAMETER_CAPA:
				bgpcapa := BGPCapabilities{make([]BGPCapabilityIf, 0)}
				for i < len(b)-1 && i < baseparam+parmlength {
					capatype := b[i]
					capalength := int(b[i+1])

					if i+1+capalength > len(b) {
						return nil, errors.New(fmt.Sprintf("ParseOpen: wrong capability length: %v > %v", i+1+capalength, len(b)))
					}
					capa := b[i+2 : i+2+capalength]
					//log.Debugf("ParseOpen: Capa %v %v %v", capatype, capalength, capa)

					i += 2 + capalength

					capastruct := BGPCapability{
						Type: capatype,
						Data: capa,
					}
					capastructparsed := capastruct.ParseCapability()
					bgpcapa.BGPCapabilities = append(bgpcapa.BGPCapabilities, capastructparsed)
				}
				parameterdata = bgpcapa
			}

			bgpparameter.Data = parameterdata
			m.Parameters = append(m.Parameters, bgpparameter)
		}

	}
	return &m, nil
}

func CraftOpenMessage(asn uint32, holdtime uint16, identifier []byte, mplist []BGPCapability_MP, addpathlist []AddPath, routerefresh bool) *BGPMessageOpen {
	asn_2o := uint16(asn)
	if asn >= 65536 {
		asn_2o = 23456
	}
	// Check for identifier = 4: "bytes",
	open := &BGPMessageOpen{
		Version:    4,
		ASN:        asn_2o,
		HoldTime:   holdtime,
		Identifier: identifier,
		Parameters: make([]BGPParameter, 1)}

	ptr := &BGPCapabilities{make([]BGPCapabilityIf, 0)}
	ptr.BGPCapabilities = append(ptr.BGPCapabilities, &BGPCapability_ASN{asn})

	if mplist != nil && len(mplist) > 0 {
		for i := range mplist {
			ptr.BGPCapabilities = append(ptr.BGPCapabilities, &mplist[i])
		}
	}

	if addpathlist != nil && len(addpathlist) > 0 {
		addpathcapa := BGPCapability_ADDPATH{AddPathList: addpathlist}
		ptr.BGPCapabilities = append(ptr.BGPCapabilities, addpathcapa)
	}

	if routerefresh {
		ptr.BGPCapabilities = append(ptr.BGPCapabilities, BGPCapability_ROUTEREFRESH{})
	}

	parameter := BGPParameter{
		Type: PARAMETER_CAPA,
		Data: ptr,
	}

	open.Parameters[0] = parameter
	return open
}
