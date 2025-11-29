package solutions

import (
	"errors"
	"fmt"
)

// https://cryptopals.com/sets/2/challenges/15
func Easy() {
	fmt.Println("=============================\n\t  EASY (15)\n=============================")
	str1 := "ICE ICE BABY\x04\x04\x04\x04"
	str2 := "ICE ICE BABY\x05\x05\x05\x05"
	str3 := "ICE ICE BABY\x01\x02\x03\x04"
	test_stripping(str1)
	test_stripping(str2)
	test_stripping(str3)
	str4 := "\x02\x02"
	test_stripping(str4)
}

func strip_padding(msg string) (string, error) {
	if len(msg) == 0 {
		return msg, nil
	}
	padding_len := msg[len(msg)-1]
	first_pad := len(msg) - int(padding_len)

	if first_pad < 0 {
		return "", errors.New("padding invalid")
	}
	for i := first_pad; i < len(msg); i++ {
		if msg[i] != padding_len {
			return "", errors.New("padding invalid")
		}
	}
	return msg[:first_pad], nil
}

func test_stripping(msg string) {
	fmt.Printf("Testing stripping for %q\n", msg)
	unpadded, err := strip_padding(msg)
	if err != nil {
		fmt.Println("Got error:", err)
	} else {
		fmt.Println("Correctly unpadded message", unpadded)
	}
}
