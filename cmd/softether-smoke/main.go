package main

// Smoke test for the native SoftEther backend: it logs in, leases an address
// over the in-process L2 stack, and dials a target without touching the
// operating system.
//
//	go run ./cmd/softether-smoke <host> <port> <hub> <user> <target>
//
// The password is read from SOFTETHER_PASSWORD.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/softether"
	"github.com/qy/easyconnect/internal/vpn"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: softether-smoke <host> <port> <hub> <user> <target>")
		os.Exit(2)
	}
	var port int
	fmt.Sscanf(os.Args[2], "%d", &port)

	point := model.AccessPoint{
		Kind:     model.KindSoftEther,
		Name:     "smoke",
		Server:   os.Args[1],
		Port:     port,
		Hub:      os.Args[3],
		Username: os.Args[4],
	}
	creds := vpn.Credentials{Login: os.Getenv("SOFTETHER_PASSWORD")}
	if creds.Login == "" {
		fmt.Fprintln(os.Stderr, "SOFTETHER_PASSWORD is empty")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	start := time.Now()
	sess, err := softether.Connect(ctx, point, creds)
	if err != nil {
		fmt.Println("FAIL connect:", err)
		os.Exit(1)
	}
	defer sess.Close()
	info := sess.Info()
	fmt.Printf("connected in %s, client ip=%s, routes=%v\n",
		time.Since(start).Round(time.Millisecond), info.ClientIP, info.NodeGroups)

	target := os.Args[5]
	dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dcancel()
	conn, err := sess.Dial(dctx, "tcp", target)
	if err != nil {
		fmt.Println("DIAL:", err)
		os.Exit(1)
	}
	conn.Close()
	fmt.Println("DIAL OK")
}
