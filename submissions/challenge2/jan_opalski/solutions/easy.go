package solutions

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Client struct {
	a, p, g, A *big.Int
}

func newClient(p *big.Int, g *big.Int) Client {
	a, _ := rand.Int(rand.Reader, p)
	A := big.NewInt(0)
	A.Exp(g, a, p)
	return Client{
		a,
		p,
		g,
		A,
	}
}

func (c Client) publicKey() *big.Int {
	return c.A
}

func (c Client) generateSessionKey(B *big.Int) *big.Int {
	var s big.Int
	s.Exp(B, c.a, c.p)
	return &s
}

func Easy() {
	fmt.Println("=============================\n\t  EASY (33)\n=============================")
	p, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)
	// client 1
	client1 := newClient(p, g)
	A := client1.publicKey()
	// client 2
	client2 := newClient(p, g)
	B := client2.publicKey()
	// client 1 doesn't know b, but can calculate g**(a*b) as B**a
	s1 := client1.generateSessionKey(B)
	fmt.Println("Session key for client1:", s1.Text(16))
	// client 2 doesn't know a, but can calculate g**(a*b) as A**b
	s2 := client2.generateSessionKey(A)
	fmt.Println("Session key for client2:", s2.Text(16))
	if s1.Cmp(s2) == 0 {
		fmt.Println("These values are equal")
	} else {
		panic("These values are different. It doesn't work")
	}
}
