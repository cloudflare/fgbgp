package main

import (
	"flag"
	"fmt"
	server "github.com/cloudflare/fgbgp/server"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
)

const AppVersion = "fgbgp 2017.8.0"

var (
	LogLevel = flag.String("loglevel", "info", "Log level")
	BgpAddr  = flag.String("bgp.addr", ":1179", "Listen address")
	Version  = flag.Bool("version", false, "Print version")
)

func main() {
	flag.Parse()

	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	m := server.NewManager(65001, net.ParseIP("1.2.3.4"), false, false)
	m.UseDefaultUpdateHandler(10)
	err := m.NewServer(*BgpAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hello %v\n", m)
	m.Start()
}
