// Copyright © 2013 Emery Hemingway

// adc_ping is a Munin plugin for graphing ADC hub statistics
//
// A hub URL must be specified through the environment variable
// ${hub_url}. This url is used in graph labels so try not to
// use 'localhost.
//
// An example config
// [adc_ping]
// env.hub_url adc://some-host.net:1511
package main

import (
	"fmt"
	"github.com/3M3RY/go-adc/adc"
	"net/url"
	"os"
)

func printConfig() {
	fmt.Println("multigraph users")
	fmt.Println("graph_title Users")
	fmt.Println("graph_vlabel users")
	fmt.Println("graph_args --base 1000 --lower-limit 0")
	fmt.Println("graph_scale yes")

	fmt.Println("user_count.label Users")
	fmt.Println("user_count.draw AREA")

	fmt.Println("multigraph sharesize")
	fmt.Println("graph_title Share Size")
	fmt.Println("graph_vlabel bytes")
	fmt.Println("graph_args --base 1024 --lower-limit 0")
	fmt.Println("graph_scale yes ")

	fmt.Println("share_size_total.label Total Share")
	fmt.Println("share_size_total.draw AREA")

	fmt.Println("share_size_average.label Average User Share")
	fmt.Println("share_size_average.draw LINE")

	fmt.Println("multigraph filecount")
	fmt.Println("graph_title File Count")
	fmt.Println("graph_args --lower-limit 0")
	fmt.Println("graph_vlabel files")

	fmt.Println("file_count_total.label Total Shared Files")
	fmt.Println("file_count_total.draw AREA")
	fmt.Println("file_count_average.label Average Shared Files")
	fmt.Println("file_count_average.draw LINE")

	fmt.Println("multigraph filesize")
	fmt.Println("graph_title Average File Size")
	fmt.Println("graph_vlabel bytes")
	fmt.Println("graph_args --base 1024 --lower-limit 0")
	fmt.Println("graph_scale yes")

	fmt.Println("file_size_average.label Average File Size")
	fmt.Println("file_size_average.draw LINE")
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "config" {
			printConfig()
			os.Exit(0)
		} else {
			fmt.Println("unhandled argument", os.Args[1])
			os.Exit(-1)
		}
	}

	us := os.Getenv("hub_url")
	if len(us) == 0 {
		fmt.Println("Error: $hub_url was empty")
		os.Exit(-1)
	}
	hubUrl, err := url.Parse(us)
	if err != nil {
		fmt.Println("$hub_url error", err)
		os.Exit(-1)
	}

	info, err := adc.Ping(hubUrl)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	var (
		userCount      uint64
		totalShareSize uint64
		totalFileCount uint64
	)
	var n int

	n, err = fmt.Sscan(info["UC"].String(), &userCount)
	if n != 1 || err != nil {
		fmt.Printf("error: could not parse user count", err)
		os.Exit(-1)
	}

	n, err = fmt.Sscan(info["SS"].String(), &totalShareSize)
	if n != 1 || err != nil {
		fmt.Printf("error: could not parse share size", err)
		os.Exit(-1)
	}

	n, err = fmt.Sscan(info["SF"].String(), &totalFileCount)
	if n != 1 || err != nil {
		fmt.Printf("error: could not parse file count", err)
		os.Exit(-1)
	}

	fmt.Println("multigraph users")
	fmt.Println("user_count.value", info["UC"])

	fmt.Println("multigraph sharesize")
	fmt.Println("share_size_total.value", info["SS"])
	fmt.Println("share_size_average.value", totalShareSize/userCount)

	fmt.Println("multigraph filecount")
	fmt.Println("file_count_total.value", info["SF"])
	fmt.Println("file_count_average.value", totalFileCount/userCount)

	fmt.Println("multigraph filesize")
	fmt.Println("file_size_average.value", totalShareSize/totalFileCount)
	os.Exit(0)
}
