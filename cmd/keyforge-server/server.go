package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/keyforgery/KeyForge/crypto/hibs"
	"github.com/keyforgery/KeyForge/utils"
)

var (
	keyDirectory string
	privateFile  string
	publicFile   string
)

const (
	// TODO: parameterize these in a config file
	sock         = "/tmp/go.sock"
	ExpiryTime   = 15
	ChunksPerDay = 24 * 60 / ExpiryTime // number of minute chunks per day
	DNS_ATTEMPTS = 4
	BACKOFF_TIME = 10 * time.Second
)

// Global HIBS for this server
var H *hibs.GSHIBE

type Server struct {
	DNS string

	// Cache of DNS results for various selector domains
	Cache DNSCache
}

type SigArgs struct {
	Sha256               string // A sha256 sum of the message to be signed
	ReceiverEmailAddress string // The full email address of the receiver
}

type SigReply struct {
	Signature string // a b64 encoded signature
	DNS       string // The domain of the sender
	Expiry    string // A string that includes the Y/M/D/M block
	Success   bool
}

type VerifyReply struct {
	Answer       bool
	Success      bool
	IsExpired    bool
	VerifyFailed bool
	ErrorMessage string
}

type VerifyArgs struct {
	Sha256             string // A sha256 sum of the message to be verified
	SenderEmailAddress string // The email address of the receiver
	DNS                string // The DNS we should use to look up params (specified in the header)
	Signature          string // The sig
	Expiry             string // The time at which the key expires
}

func setError(reply *VerifyReply) {
	reply.VerifyFailed = true
}

func (s *Server) Verify(args VerifyArgs, reply *VerifyReply) error {

	now := time.Now().UTC()

	if s.Cache == nil {
		s.Cache = NewDNSCache()
	}

	// Parse expiry
	timeAndChunk := strings.Split(args.Expiry, ",")

	if len(timeAndChunk) != 2 {
		setError(reply)
		return nil
	}

	expiryDay, err := time.Parse(time.UnixDate, timeAndChunk[0])

	if err != nil {
		setError(reply)
		return nil
	}

	var chunk int

	// Extract the chunk
	if t, err := strconv.Atoi(timeAndChunk[1]); err != nil {
		// Chunk is not parsable
		setError(reply)
		return nil
	} else {
		chunk = t
	}

	fullExpiry := expiryDay.Add(time.Duration(chunk*ExpiryTime) * time.Minute)
	// Determine if expiry is < the current time
	if now.After(fullExpiry) {
		fmt.Println(fullExpiry)
		fmt.Println(now)

		// this is expired, no reason to fully verify
		setError(reply)
		reply.IsExpired = true
		reply.VerifyFailed = true
		reply.ErrorMessage = "Key expired"
		return nil
	}

	cyear, _month, cday := expiryDay.Date()
	cmonth := int(_month)

	path := utils.FomatPath(cyear, cmonth, cday, chunk)

	fmt.Println("path parsed as: ", path)

	err, mpk, public := s.Cache.GetPublicFromDNS(args.DNS, path[:3])

	if err != nil {
		// failure, cannot get details from dns
		setError(reply)
		reply.ErrorMessage = "Could not resolve DNS for " + args.DNS
		fmt.Println(err)
		return nil
	}

	sigParts := strings.Split(args.Signature, ",")

	qvalues := public[:]
	qvalues = append(qvalues, sigParts[1])

	err, sig := hibs.GSSigFromPublic(sigParts[0], qvalues)
	if err != nil {
		// Failure, cannot get details from dns
		setError(reply)
		return nil
	}

	var h hibs.GSHIBE

	err = h.SetupPublicFromString(mpk)

	if err != nil {
		// failure, cannot get details from dns
		setError(reply)
		reply.ErrorMessage = "Public key at " + args.DNS + " could not be parsed"
		return nil
	}

	reply.Success = true
	if h.Verify(*sig, args.Sha256, path[:]) {
		// success!
		log.Println("Succeessfully verified ", args.Sha256)
		reply.Answer = true
	} else {
		log.Println("Succeeded in parsing, but failed to verify ", args.Sha256)
		reply.Answer = false
	}

	return nil
}

func (s *Server) Sign(args *SigArgs, reply *SigReply) error {
	/*
		1. Figure out the time at which this thing should expire (now + 15 minutes)
		2. Sign the thing using our hibs and the correct y/m/d timestamp

	*/
	now := time.Now().UTC()

	expiry := now.Add(time.Minute * ExpiryTime)

	// Let's truncate the time
	cyear, _month, cday := expiry.Date()
	cmonth := int(_month)

	hour, minute, _ := expiry.Clock()
	chunk := int((hour*60 + minute) / ExpiryTime)

	path := utils.FomatPath(cyear, cmonth, cday, chunk)

	signature, qvalues := H.ExportSign(args.Sha256, path[:], 1)

	reply.Signature = signature + "," + strings.Join(qvalues, ",")
	reply.Success = true
	reply.Expiry = now.Truncate(time.Hour*24).Format(time.UnixDate) + "," + path[3]

	fmt.Println("Signing current with expiry", reply.Expiry)

	return nil
}

func loadHIBE() *hibs.GSHIBE {

	var local hibs.GSHIBE
	// read sk file
	sk, _ := ioutil.ReadFile(privateFile)
	local.SetupPrivateFromString(string(sk))

	// read pk file
	// split pk file on ',' delims, first element is our encoded pk
	pk, err := ioutil.ReadFile(publicFile)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pk))
	fmt.Println("keyforgefile")

	pubkeyMap := makeTagValueMap(string(pk))

	encodedPK := pubkeyMap["public"]
	local.SetupPublicFromString(encodedPK)

	H = &local
	return H
}
