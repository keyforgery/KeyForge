/*
keyforge-generate

keyforge-generate creates the tree layout, as well as a Master Secret and
Master Public parameters necessary for keyforge.

Ideally, one should work in time limits that allow for low Time To Live (TTL)
of the message's signature, while also keeping the bandwidth required for
dissemination of expiry keys and public parameter to a minimum.

The tree layout is created with deference to administrator preferences;
with the tree depth is provided by the user as well as the TTL.

Example with Gentry Silverberg w/a BLS curve:
Each signature ~= 97 bytes
Each node in public params ~= 49 bytes
Each secret key ~= 49 bytes

How we're going to do this:

- MSK goes into a _secret file

- MPK goes into a _keyforge file
	- P0, Q0
	- Contains another 2 year keys
	- there will be one of these
	== 4*49 = ~196 bytes

- <Year>._keyforge file
	- This includes all 12 KeyForge pubkeys for that year's months
	- there will be one of these
	== 12*49 = 588 bytes

- <YearMonth>._KeyForge file
	- Includes all ~31 keys for each day in that month
	- There will be 12 of these
	== ~49*31 = 1478 bytes

*/
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/keyforgery/KeyForge/crypto/hibs"
	"github.com/keyforgery/KeyForge/utils"
)

const (
	pubHelp    = "Specifies the directory for public and private keyfiles, default = ~/.KeyForge/"
	homeDir    = "~/.KeyForge/"
	pubKeyFile = "_KeyForge"
	secKeyFile = "MasterSecret"
	secKeyDir  = "secret"
	pubKeyDir  = "public"
	finalHelp  = `
Success! The keys have been written to the directories you've provided. Please upload 
these keys directly to your DNS. The files themselves have
been named corresponding to how they should be resolved; e.g. the file named _KeyForge should
resolve to _KeyForge.yourdomain.com.
`
)

var directory string

type Month struct {
	pub  string
	days map[int]string
}

type Year struct {
	pub    string
	months map[int]*Month
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func trimComma(s string) string {
	if last := len(s) - 1; last >= 0 && s[last] == ',' {
		s = s[:last]
	}
	return s
}

func chunkify(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

func writeToPubkeyFile(filename string, input string) {
	input = trimComma(input)

	input = input + "EOM"

	splitdata := chunkify(input, 1000)

	for i, data := range splitdata {
		currentfilename := filename + "_" + strconv.Itoa(i)

		fullpath := path.Join(directory, currentfilename)

		if filename != "" {
			fullpath += "."
			fullpath += pubKeyFile
		} else {
			fullpath = path.Join(directory, pubKeyFile)
		}
		fmt.Println(fullpath)

		os.MkdirAll(filepath.Dir(fullpath), os.ModePerm)

		err := ioutil.WriteFile(fullpath, []byte(data), 0644)
		check(err)
	}
}

// Dump h's MSK to file
func dumpPrivate(h hibs.GSHIBE) {
	fullpath := path.Join(directory, "private")
	fullpath = path.Join(fullpath, "private")

	os.MkdirAll(filepath.Dir(fullpath), os.ModePerm)
	err := ioutil.WriteFile(fullpath, []byte(h.ExportMasterPrivate()), 0644)
	check(err)
}

// Collects two years worth of keys
func collectKeys(h hibs.GSHIBE) map[int]*Year {

	years := make(map[int]*Year)

	currentDate := time.Now().UTC()
	oneDay := time.Hour * 24

	// Get each key for 365*2
	for daycount := 0; daycount < 365; daycount++ {

		cyear, _month, cday := currentDate.Date()
		cmonth := int(_month)

		ids := [...]string{
			utils.FormatYear(cyear),
			utils.FormatDig(cmonth),
			utils.FormatDig(cday)}

		// Extract to the day
		dayNode := h.ExtractPath(ids[:])
		monthNode := dayNode.Parent()
		yearNode := monthNode.Parent()

		year, yok := years[cyear]
		if !yok {
			var newYear Year
			year = &newYear
			year.pub = yearNode.Params()
			years[cyear] = year
			year.months = make(map[int]*Month, 0)
		}

		m, yok := years[cyear].months[cmonth]
		if !yok {
			var month Month
			// current month is uninit
			month.pub = monthNode.Params()
			month.days = make(map[int]string)
			year.months[cmonth] = &month
			m = &month
		}

		m.days[cday] = dayNode.Params()

		currentDate = currentDate.Add(oneDay)
	}

	fmt.Println()
	fmt.Println("Generated all public parameters necessary between now and", currentDate)
	fmt.Println("This should hold you over for about a year.")
	fmt.Println("After that date, please upload new values / update your KeyForge Keys")
	fmt.Println()

	return years
}

func formatTagValue(tag, value string) string {
	return fmt.Sprintf("%s=%s", tag, value)
}

// Dump various Q values to file(s)
func dumpPublic(h hibs.GSHIBE) {
	years := collectKeys(h)

	// Write everything to the files
	yearKeys := ""

	// Holds all year strings in one dir
	for yearNumber, yearObject := range years {
		yearstr := utils.FormatYear(yearNumber)

		yearKeys += formatTagValue(yearstr, yearObject.pub) + ","

		// dump the year's month keys
		monthKeys := ""
		for monthNumber, mv := range yearObject.months {
			monthstr := utils.FormatDig(monthNumber)
			monthKeys += formatTagValue(monthstr, mv.pub) + ","

			// get the month's keys
			dayKeys := ""
			for dayNumber, dv := range mv.days {
				dayKeys += formatTagValue(utils.FormatDig(dayNumber), dv) + ","
			}

			monthFileName := yearstr + monthstr
			writeToPubkeyFile(monthFileName, dayKeys)
		}

		writeToPubkeyFile(yearstr, monthKeys)
	}

	// Dump h's MPK and years to the same file
	writeToPubkeyFile("", formatTagValue("public", h.ExportPublic())+","+yearKeys)
}

func main() {
	// Create params

	// input:
	configLoc, milterSock, kfSock, keyDir := utils.ConfigFlags()

	err, config := utils.SetupConfig(configLoc, keyDir, milterSock, kfSock)

	check(err)

	directory = config.KeyDirectory

	fmt.Println("keyforge files will be placed in ", directory)

	// Setup MPK/MSK
	var h hibs.GSHIBE
	h.Setup()

	// Dump public params
	dumpPublic(h)
	dumpPrivate(h)

	fmt.Println(finalHelp)
}
