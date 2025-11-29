package main

import (
	"challenge1/solutions"
	"flag"
)

func main() {
	easyFlag := flag.Bool("easy", false, "launch solution of easy task")
	mediumFlag := flag.Bool("medium", false, "launch solution of medium task")
	hardFlag := flag.Bool("hard", false, "launch solution of hard task")
	mediumSeedFlag := flag.Int("seed", 19650218, "seed for medium task")
	flag.Parse()
	all := false
	if !(*easyFlag || *mediumFlag || *hardFlag) {
		flag.Usage()
		all = true
	}
	if *easyFlag || all {
		solutions.Easy()
	}
	if *mediumFlag || all {
		solutions.Medium(uint32(*mediumSeedFlag))
	}
	if *hardFlag || all {
		solutions.Hard()
	}
}
