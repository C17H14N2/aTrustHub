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

	// HOLD=<seconds> keeps the session open and re-dials every few seconds, to
	// prove the keep-alive keeps the hub from dropping it.
	hold := 0
	fmt.Sscanf(os.Getenv("SOFTETHER_HOLD"), "%d", &hold)
	deadline := time.Now().Add(time.Duration(hold) * time.Second)

	// MODE=combo keeps one connection open and also opens a second one every
	// few seconds: with a live connection the hub's NAT entry stays warm, so
	// this shows whether fresh dials work while traffic is flowing.
	if os.Getenv("SOFTETHER_MODE") == "combo" {
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		hold, err := sess.Dial(dctx, "tcp", target)
		dcancel()
		if err != nil {
			fmt.Println("DIAL:", err)
			os.Exit(1)
		}
		defer hold.Close()
		fmt.Println("held connection open")
		tick := time.NewTicker(8 * time.Second)
		defer tick.Stop()
		for time.Now().Before(deadline) {
			select {
			case <-sess.Done():
				fmt.Println("SESSION DIED:", sess.Err())
				os.Exit(1)
			case <-tick.C:
				cctx, ccancel := context.WithTimeout(context.Background(), 8*time.Second)
				c, derr := sess.Dial(cctx, "tcp", target)
				ccancel()
				if derr != nil {
					fmt.Printf("[%3ds] fresh dial failed: %v\n", int(time.Since(start).Seconds()), derr)
				} else {
					c.Close()
					fmt.Printf("[%3ds] fresh dial ok\n", int(time.Since(start).Seconds()))
				}
			}
		}
		return
	}

	// MODE=hold opens one connection and keeps it open, which separates a
	// per-connection limit from a time-based one.
	if os.Getenv("SOFTETHER_MODE") == "hold" {
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := sess.Dial(dctx, "tcp", target)
		dcancel()
		if err != nil {
			fmt.Println("DIAL:", err)
			os.Exit(1)
		}
		defer conn.Close()
		fmt.Println("long-lived connection open")
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for time.Now().Before(deadline) {
			select {
			case <-sess.Done():
				fmt.Println("SESSION DIED:", sess.Err())
				os.Exit(1)
			case <-tick.C:
				if _, werr := conn.Write([]byte{0x00}); werr != nil {
					fmt.Printf("[%3ds] write failed: %v\n", int(time.Since(start).Seconds()), werr)
					os.Exit(1)
				}
				fmt.Printf("[%3ds] connection alive\n", int(time.Since(start).Seconds()))
			}
		}
		return
	}

	for round := 1; ; round++ {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := sess.Dial(dctx, "tcp", target)
		dcancel()
		if err != nil {
			fmt.Printf("[%3ds] dial: %v\n", int(time.Since(start).Seconds()), err)
		} else {
			conn.Close()
			fmt.Printf("[%3ds] dial ok\n", int(time.Since(start).Seconds()))
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-sess.Done():
			fmt.Println("SESSION DIED:", sess.Err())
			os.Exit(1)
		case <-time.After(10 * time.Second):
		}
	}
}
