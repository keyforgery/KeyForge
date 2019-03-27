package utils

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
)

type Configuration struct {
	KeyDirectory  string `json:"KeyDir"`
	MilterMTAPipe string `json:"MilterPipeLocation"` // Where milter <-> MTA pipe exists
	KFPipe        string `json:"KeyForgePipeFile"`   // Where KF server <-> milter pipe exists
}

const (
	DefaultConfigLoc  = "~/.KeyForge/config.json"
	DefaultMilterSock = "/tmp/milter.sock"
	DefaultKFSock     = "/tmp/kf.sock"
	DefaultKeyDir     = "~/.KeyForge/"
	DefaultDNS        = "_KeyForge.example.com"
	ConfigHelp        = "Specifies the configfile location"
	KeyDirHelp        = "Specifies the directory for public and private keyfiles"
	MilterHelp        = "Specifies the location of the Milter <-> MTA pipe"
	KFSockHelp        = "Specifies the location of the KeyForge <-> milter pipe"
	KFDNSHelp         = "Specifies the DNS of our local server"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ConfigFlags() (configLoc, milterSock, kfSock, keyDir string) {
	milterSock = *flag.String("m", DefaultMilterSock, MilterHelp)
	configLoc = *flag.String("c", DefaultConfigLoc, ConfigHelp)
	kfSock = *flag.String("k", DefaultKFSock, KFSockHelp)
	keyDir = *flag.String("d", DefaultKeyDir, KeyDirHelp)
	flag.Parse()

	if keyDir == DefaultKeyDir {
		usr, err := user.Current()
		check(err)
		keyDir = path.Join(usr.HomeDir, ".KeyForge/")
	}

	if configLoc == DefaultConfigLoc {
		usr, err := user.Current()
		check(err)
		configLoc = path.Join(usr.HomeDir, ".KeyForge/")
		configLoc = path.Join(configLoc, "config.json")
	}

	return
}

func SetupConfig(ConfigLoc, KeyDir, MilterPipe, KFPipe string) (error, *Configuration) {
	// Sets up the overall config at a particular location

	Config := Configuration{KeyDir, MilterPipe, KFPipe}

	b, err := json.MarshalIndent(Config, "", "  ")

	if err != nil {
		// Unable to parse for some reason, should never happen
		return err, nil
	}

	if _, err2 := os.Stat(ConfigLoc); os.IsNotExist(err2) {
		dir, _ := filepath.Split(ConfigLoc)
		os.MkdirAll(dir, os.ModePerm)
	}

	err2 := ioutil.WriteFile(ConfigLoc, b, 0644)

	return err2, &Config
}

func ReadConfig(ConfigLoc string) (error, *Configuration) {
	// Reads the overall config from a particular location

	file, err := os.Open(ConfigLoc)

	if err != nil {
		return nil, nil
	}

	defer file.Close()
	decoder := json.NewDecoder(file)
	Config := Configuration{}
	err = decoder.Decode(&Config)

	if err != nil {
		return nil, nil
	}

	return nil, &Config
}
