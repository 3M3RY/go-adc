package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/3M3RY/go-adc/adc"
	"github.com/3M3RY/go-tiger"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

var ( // Commandline switches
	searchTTH      string
	outputFilename string
	start          time.Time
	searchTimeout  time.Duration
	compress       bool
)

func init() {
	flag.StringVar(&outputFilename, "output", "", "output download to given file")
	flag.DurationVar(&searchTimeout, "timeout", time.Duration(8)*time.Second, "ADC search timeout")
	// NOT TESTED WITH A CLIENT THAT COMPLIES WITH COMPRESSION REQUEST
	flag.BoolVar(&compress, "compress", false, "EXPERIMENTAL: compress data transfer")
	start = time.Now()
}

func main() {
	flag.Parse()
	if len(os.Args) == 1 {
		fmt.Println(os.Args[0], "is a utility for downloading files from ADC hubs as well as traditional http and https services.")
		fmt.Println("It may be used as the Portage fetch command by adding the following to make.conf:")
		fmt.Println("FETCHCOMMAND=\"adcget -output \\\"\\${DISTDIR}/\\${FILE}\\\" \\\"\\${URI}\\\"\"")
		fmt.Println("\nUsage:", os.Args[0], "[OPTIONS] URL")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(-1)
	}

	u, err := url.Parse(flag.Arg(0))
	if err != nil {
		fmt.Println("URL error", err)
		os.Exit(-1)
	}

	logger := log.New(os.Stderr, "\r", 0)

	switch u.Scheme {
	case "adc", "adcs", "magnet":
	case "http":
		httpClient(u)
	case "https":
		httpClient(u)
	default:
		logger.Fatalln("Unsupported or unknown url scheme:", u.Scheme)
	}

	q := u.Query()

	if outputFilename == "" {
		outputFilename = q.Get("dn")
		if outputFilename == "" {
			fmt.Println("Filename not specified in URL nor -output flag.")
			os.Exit(1)
		}
	}

	var tth *adc.TreeHash
	if s := q.Get("xt"); len(s) != 54 || s[:15] != "urn:tree:tiger:" {
		fmt.Println("Invalid hash:", s)
		os.Exit(1)
	} else {
		tth, err = adc.NewTreeHash(s[15:])
		if err != nil {
			fmt.Println("Invalid hash:", s[15:], err)
			os.Exit(1)
		}
	}

	var fileSize uint64
	if xs := q.Get("xl"); xs != "" {
		fileSize, err = strconv.ParseUint(xs, 10, 64)
		if err != nil {
			fmt.Println("Invalid file size:", xs)
			os.Exit(1)
		}
	}
	fileSize += 0

	if xs := q.Get("xs"); xs == "" {
		logger.Fatalln("Hub address not specified in URL (append '&xs=adc://[hub address]:[hub port]' to the url)")
	} else {
		u, err = url.Parse(xs)
	}
	if err != nil {
		logger.Fatalln("Error parsing URI XS", err)
	}

	switch u.Scheme {
	case "adc", "adcs":
	default:
		logger.Fatalln("Unsupported or unknown url scheme:", u.Scheme)
	}

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("error: could not generate client PID, %s\n", err)
	}
	hash := tiger.New()
	fmt.Fprint(hash, hostname, os.Getuid)
	pid := adc.NewPrivateID(hash.Sum(nil))

	cu, _ := user.Current()

	myInfo := adc.FieldMap{
		"NI": cu.Username,
	}

	hub, err := adc.NewHubClient(u, pid, myInfo)
	if err != nil {
		fmt.Printf("Could not connect; %s\n", err)
		return
	}

	var done chan error
	search := adc.NewSearch()
	search.AddTTH(tth)
	hub.Send(search)

	select {
	case <-done:
		return
	}

	/*
		config.Compress = compress
		dispatcher, _ := adc.NewDownloadDispatcher(config, logger)
		search.SetResultChannel(dispatcher.ResultChannel())
		done = dispatcher.FinalChannel()

		search.Send(hub)
		results := search.Results()

		for {
			select {
			case r := <-results:
				dispatcher.AddResult(r)

			case size := <-done:
				fmt.Printf("\nDownloaded %d bytes in %s\n", size, time.Since(start))
				os.Exit(0)
			}
		}
	*/
}

func httpClient(url *url.URL) {
	var fileName string
	if fmt.Sprint(outputFilename) == "" {
		elements := strings.Split(url.Path, "/")
		fileName = elements[len(elements)-1]
		if fmt.Sprint(outputFilename) == "" {
			outputFilename = fileName
		}
	}

	file, err := os.Create(outputFilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	res, err := http.Get(url.String())
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	w := bufio.NewWriter(file)

	n := int64(1)
	for n > 0 {
		n, err = io.Copy(w, res.Body)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	}
	w.Flush()
	//fmt.Printf("\nDownloaded %d bytes in %s\n", n, time.Since(start))
	os.Exit(0)
}
