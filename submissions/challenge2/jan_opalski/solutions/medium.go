package solutions

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"slices"
)

func addPadding(data []byte, blocksize int) []byte {
	toPad := blocksize - (len(data) % blocksize)
	if toPad < blocksize {
		for range toPad {
			data = append(data, byte(toPad))
		}
	}
	return data
}

// returns mac and list of all blocks for convenience
func getCBCMAC(message []byte) ([]byte, [][]byte) {
	messageClone := make([]byte, 0)
	messageClone = append(messageClone, message...)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, aes.BlockSize)
	block, _ := aes.NewCipher(key)
	data := addPadding(messageClone, aes.BlockSize)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(data, data)
	blocks := make([][]byte, 0)
	for i := 0; i < len(data); i += aes.BlockSize {
		blocks = append(blocks, data[i:i+aes.BlockSize])
	}
	return data[len(data)-aes.BlockSize:], blocks
}

func xorSlices(s1 []byte, s2 []byte) []byte {
	n := len(s1)
	res := make([]byte, n)
	for i := range n {
		res[i] = s1[i] ^ s2[i]
	}
	return res
}

func Medium() {
	fmt.Println("=============================\n\t MEDIUM (50)\n=============================")
	message := []byte("alert('MZA who was that?');\n")
	desiredHash, ogBlocks := getCBCMAC(message)
	fmt.Printf("Looking for code with MAC %x\n", desiredHash)
	// Adding // at the beginning so that the rest of line is a comment
	wanted := []byte("alert('Ayo, the Wu is back!');//")
	// I want my final code to look like this:
	// [actual code][padding to end block][fabricated block which will produced desired MAC]
	wantedPadded := addPadding(wanted, aes.BlockSize)
	_, newBlocks := getCBCMAC(wantedPadded)
	// Fabricated block will be xored with newBlocks[1] and I want it to produce same result
	// as did second block of original message ^ ogBlocks[0].
	// Therefore I need message ^ ogBlocks[0] ^ newBlocks[1]
	wantedPadded = append(wantedPadded, xorSlices(
		xorSlices(newBlocks[1], ogBlocks[0]),
		addPadding(message[aes.BlockSize:], aes.BlockSize))...,
	)
	res, _ := getCBCMAC(wantedPadded)
	fmt.Printf("Got code with MAC %x\n", res)
	if slices.Compare(res, desiredHash) != 0 {
		fmt.Println("Exploit didn't work")
	} else {
		fmt.Println("Exploit works, writing code to medium.js")
		f, err := os.Create("medium.js")
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.Write(wantedPadded)
		// I verified produced code is accepted by my browser (Firefox)
	}
}
