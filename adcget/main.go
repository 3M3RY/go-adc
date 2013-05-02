package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

import "code.google.com/p/go-adc/adc"
import "code.google.com/p/go-tiger/tiger"

func main() {
	flag.Parse()

	hubUrl := flag.Arg(0)
	if hubUrl == "" {
		fmt.Println("No hub address specified, exiting.")
		return
	}

	hashToFind := flag.Arg(1)
	if hashToFind == "" {
		fmt.Println("No file hash specified, exiting.")
		return
	}

	outputFilename := flag.Arg(2)
	if outputFilename == "" {
		fmt.Println("No output file hash specified, exiting.")
		return
	}

	// Generate PID
	// A client PID should be persist between sessions and between hubs.
	// This utility is intended to be run from scripts by non-users accounts,
	// so storing this PID becomes difficult as you dont want someone to replicate
	// a host system and have fetches not work because there is a PID collision 
	// with other replicants using the same hub, thus I'll just hash the hostname
	// for now, which is insecure as the hostname can be publicly known.
	// 
	// Perhaps it is best to read the PID from the file ./.adc_pid_::hostname::
	// if it is present, otherwise hash the current hostame and system time, then
	// write that to the afformentioned file.
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("error: could not generate client PID, %s\n", err)
	}
	hash := tiger.New()
	fmt.Fprint(hash, hostname)
	pid := adc.NewPrivateID(hash.Sum(nil))

	//dispatcher, _ := adc.NewDownloadDispatcher(outputFilename)
	//resultChan := dispatcher.ResultChannel()

	hub, err := adc.NewHub(hubUrl, pid)
	if err != nil {
		fmt.Printf("Could not connect; %s\n", err)
		return
	}
	err = hub.Open()
	if err != nil {
		fmt.Printf("Could not connect; %s\n", err)
		return
	}
	
	//hub.SearchByTTR(hashToFind, resultChan)
	time.Sleep(1*time.Hour)

}
