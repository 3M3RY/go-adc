package adc_test

import (
	"fmt"
	"github.com/3M3RY/go-adc/adc"
)

func ExampleFieldMap() {
	inf := make(adc.FieldMap)
	inf["NI"] = "Joe Blow"
	inf["DE"] = "just your average guy"
	fmt.Println(inf)
	fmt.Printf("%v\n", inf)
	fmt.Printf("%s\n", inf)
	// Output:
	// NI:Joe Blow DE:just your average guy
	// NI:Joe Blow DE:just your average guy
	// NIJoe\sBlow DEjust\syour\saverage\sguy
}

func ExampleFieldSlice() {
	inf := make(adc.FieldSlice, 1)
	inf[0] = "NIJoe Blow"
	inf = append(inf, "DEjust your average guy")
	fmt.Println(inf)
	fmt.Printf("%v\n", inf)
	fmt.Printf("%s\n", inf)
	// Output:
	// NIJoe Blow DEjust your average guy
	// NIJoe Blow DEjust your average guy
	// NIJoe\sBlow DEjust\syour\saverage\sguy
}
