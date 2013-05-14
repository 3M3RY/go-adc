package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

import "code.google.com/p/go-adc/adc"
import "code.google.com/p/go-tiger/tiger"

var ( // Commandline switches
	searchTTH      string
	outputFilename string
	start          time.Time
)

func init() {
	flag.StringVar(&searchTTH, "tth", "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", "search for a given Tiger tree hash")
	flag.StringVar(&outputFilename, "o", "", "save search reseult to given file")
	start = time.Now()
}

func main() {

	flag.Parse()

	url, err := url.Parse(flag.Arg(0))
	if err != nil {
		fmt.Println("URL error", err)
		os.Exit(-1)
	}

	logger := log.New(os.Stderr, "\r", 0)

	switch url.Scheme {
	case "adc":
		adcClient(url, logger)
	case "adcs":
		adcClient(url, logger)
	case "http":
		httpClient(url)
	case "https":
		httpClient(url)
	default:
		logger.Fatalln("Unsupported or unknown url scheme:", url.Scheme)
	}
}

func adcClient(url *url.URL, logger *log.Logger) {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("error: could not generate client PID, %s\n", err)
	}
	hash := tiger.New()
	fmt.Fprint(hash, hostname, os.Getuid)
	pid := adc.NewPrivateID(hash.Sum(nil))

	hub, err := adc.NewHub(pid, url, logger)
	if err != nil {
		fmt.Printf("Could not connect; %s\n", err)
		return
	}

	var done chan uint64
	var fileName string
	if fmt.Sprint(searchTTH) != "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ" {
		if fmt.Sprint(outputFilename) == "" {
			fmt.Println("No output file specified, exiting.")
			return
		}
		tth, err := adc.NewTigerTreeHash(searchTTH)
		if err != nil {
			logger.Fatal("Invalid TTH:", err)
		}

		dispatcher, _ := adc.NewTTHDownloadDispatcher(tth, outputFilename, logger)
		resultChan := dispatcher.ResultChannel()
		done = dispatcher.FinalChannel()
		search := adc.NewSearch(resultChan)
		search.AddTTH(tth)
		hub.Search(search)
		dispatcher.Run()

	} else {
		elements := strings.Split(url.Path, "/")
		fileName = elements[len(elements)-1]
		if fmt.Sprint(outputFilename) == "" {
			outputFilename = fileName
		}

		dispatcher, _ := adc.NewFilenameDownloadDispatcher(fileName, outputFilename, logger)
		resultChan := dispatcher.ResultChannel()
		done = dispatcher.FinalChannel()
		search := adc.NewSearch(resultChan)
		search.AddInclude(fileName)
		hub.Search(search)
		dispatcher.Run()
	}

	size := <-done
	if size == 0 {
		os.Exit(-1)
	} else {
		fmt.Printf("\nDownloaded %d bytes in %s\n", size, time.Since(start))
		os.Exit(0)
	}
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
	fmt.Println(res)

	w := bufio.NewWriter(file)
	size, err := io.Copy(w, res.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	fmt.Printf("\nDownloaded %d bytes in %s\n", size, time.Since(start))
	os.Exit(0)
}
