package main

/*

This server is a service that signs / verifies messages/hashes

The key generation only works to the Day limit. We only guarantee 15 minute liveliness of keys.
*/

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keyforgery/KeyForge/utils"
)

const pubHelp = "Specifies the directory for public and private keyfiles, default = ~/.KeyForge/"

func startKeyServer(sock string) {
	// Start and register rpc server
	keyserver := new(Server)
	// TODO: TEMPORARY HACK, FIX, MAYBE CONFIG FILES?
	keyserver.DNS = "test"
	server := rpc.NewServer()
	server.Register(keyserver)
	server.HandleHTTP(rpc.DefaultRPCPath, rpc.DefaultDebugPath)

	// Transport == unix sockets
	l, e := net.Listen("unix", sock)
	if e != nil {
		log.Fatal("listen error:", e)
		panic(e)
	}

	defer l.Close()

	// Handle the case that the process is sigterm'd:
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)

	go func(ln net.Listener, c chan os.Signal) {
		sig := <-c
		log.Printf("Caught signal %s: shutting down.", sig)
		ln.Close()
		os.Exit(0)
	}(l, sigc)

	// Inf loop that handles our rpc
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go server.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

func check(e error, message string) {
	if e != nil {
		fmt.Println(message)
		panic(e)
	}
}

func main() {
	configLoc, _, _, _ := utils.ConfigFlags()

	err, config := utils.ReadConfig(configLoc)
	keyDir := config.KeyDirectory

	check(err, "fail! Cannot read config!")

	privateFile = keyDir + "/private/private"
	publicFile = keyDir + "/_KeyForge"

	// Load our HIBE instance
	h := loadHIBE()

	// Start the keyserver
	go startKeyServer(config.KFPipe)

	// simple webserver

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	http.HandleFunc("/expire", func(w http.ResponseWriter, r *http.Request) {
		// As a demo, we display expiry info every 30 minutes
		now := time.Now().UTC()
		expiry := now.Add(time.Minute * -30)

		// Let's truncate the time
		cyear, _month, cday := expiry.Date()
		cmonth := int(_month)

		hour, minute, _ := expiry.Clock()
		chunk := int((hour*60 + minute) / 30)
		private := ""

		// Last year:
		lastYear := make([]string, 0)
		lastYear = append(lastYear, utils.FormatYear(cyear-1))
		private += h.ExportLeafPrivate(lastYear)

		// past months
		pastMonth := cmonth - 1

		for pastMonth >= 0 {
			monthPath := make([]string, 0)
			monthPath = append(monthPath, utils.FormatYear(cyear))
			monthPath = append(monthPath, utils.FormatDig(pastMonth))
			private += h.ExportLeafPrivate(lastYear)
			pastMonth -= 1
		}

		// all of the necessary chunks
		for chunk >= 0 {
			path := utils.FomatPath(cyear, cmonth, cday, chunk)
			private += h.ExportLeafPrivate(path)
			chunk -= 1
		}

		// day -1

		fmt.Fprintf(w, "Hi, the following are expiry information for anything prior to ")
		fmt.Fprintf(w, expiry.String())
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, private)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))

}
