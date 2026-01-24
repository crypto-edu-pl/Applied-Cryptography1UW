package main

import (
	"challenge2/solutions"
	"flag"
)

func main() {
	easyFlag := flag.Bool("easy", false, "launch solution of easy task")
	mediumFlag := flag.Bool("medium", false, "launch solution of medium task")
	hardFlag := flag.Bool("hard", false, "launch solution of hard task")
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
		solutions.Medium()
	}
	if *hardFlag || all {
		solutions.Hard()
	}
}
