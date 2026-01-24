package solutions

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

type Server struct {
	d, n, e *big.Int
	used    []*big.Int
}

func newServer() Server {
	p := big.NewInt(1e9 + 7)
	q := big.NewInt(1584418609)
	n := new(big.Int).Mul(p, q)
	et := new(big.Int).Mul(p.Sub(p, big.NewInt(1)), q.Sub(q, big.NewInt(1)))
	e := big.NewInt(17)
	d := new(big.Int).ModInverse(e, et)
	fmt.Printf("Public key: [0x%x 0x%x]\n", e, n)
	fmt.Printf("Private key: [0x%x 0x%x]\n", d, n)
	used := make([]*big.Int, 0)
	return Server{d, n, e, used}
}

func (s Server) publicKey() (*big.Int, *big.Int) {
	return s.e, s.n
}

func (s *Server) encrypt(msg []byte) (*big.Int, *big.Int) {
	msgBytes := hex.EncodeToString(msg)
	m, _ := new(big.Int).SetString(msgBytes, 16)
	m.Mod(m, s.n)
	c := new(big.Int).Exp(m, s.e, s.n) // c = m ** e mod n
	s.used = append(s.used, c)
	fmt.Printf("Encrypted message %x with RSA\nCiphertext: c=%x\n", m, c)
	return c, m
}

func (s *Server) decrypt(c *big.Int) *big.Int {
	// we assume server stores previous messages for some time and ties them to client
	// here for simplicity it refuses any requests to decrypt something recently encrypted
	for _, v := range s.used {
		if c.Cmp(v) == 0 {
			panic("Can't decrypt this message")
		}
	}
	return new(big.Int).Exp(c, s.d, s.n)
}

// attacker knows a ciphertext and public key, doesn't know private key
func attack(c *big.Int, server *Server) *big.Int {
	e, n := server.publicKey()
	s := big.NewInt(2) // "doesn't matter what, >1 mod N" - 2 is >1 mod N forall N>3
	cp := new(big.Int).Exp(s, e, n)
	cp.Mul(cp, c)
	fmt.Printf("Attacker asks server for decryption of c'=%x\n", cp)
	pp := server.decrypt(cp)
	p := new(big.Int).ModInverse(s, n)
	p.Mul(p, pp)
	p.Mod(p, n)
	fmt.Printf("Attacker guesses the message was %x\n", p)
	return p
}

func Hard() {
	fmt.Println("=============================\n\t  HARD (41)\n=============================")
	server := newServer()
	// Client part
	originalMsg := "This is some secret message"
	c, m := server.encrypt([]byte(originalMsg))
	// Attacker captures ciphertext
	guess := attack(c, &server)
	if m.Cmp(guess) == 0 {
		fmt.Println("Attacker guessed correctly")
	} else {
		panic("Attack didn't work")
	}
}
