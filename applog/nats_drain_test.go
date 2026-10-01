package applog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phuslu/log"
)

// logBroker implements just the NATS wire messages needed by the log shipper.
// The second PING (drain's flush) can be held so tests prove shutdown waits
// for server acknowledgement, or force-closes on timeout. No broker binary
// or new production dependency is needed.
func logBroker(t *testing.T, acknowledge <-chan struct{}) (string, <-chan []byte, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	messages := make(chan []byte, 512)
	drainPing := make(chan struct{})
	done := make(chan struct{})
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		ln.Close()
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("test broker did not stop")
		}
	})
	go func() {
		defer close(done)
		defer close(messages)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
		defer conn.Close()
		fmt.Fprint(conn, "INFO {\"server_id\":\"test\",\"max_payload\":1048576}\r\n")
		reader := bufio.NewReader(conn)
		pings := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			switch parts[0] {
			case "PING":
				pings++
				if pings == 2 {
					close(drainPing)
					select {
					case <-acknowledge:
					case <-stop:
						return
					}
				}
				if _, err := fmt.Fprint(conn, "PONG\r\n"); err != nil {
					return
				}
			case "PUB":
				n, err := strconv.Atoi(parts[len(parts)-1])
				if err != nil {
					return
				}
				body := make([]byte, n+2)
				if _, err := io.ReadFull(reader, body); err != nil {
					return
				}
				messages <- body[:n]
			}
		}
	}()
	return "nats://" + ln.Addr().String(), messages, drainPing, done
}

func waitLogShutdown(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestAppLoggerWithNATS_DrainFlushesAndWaitsForClose(t *testing.T) {
	ack := make(chan struct{})
	url, messages, ping, brokerDone := logBroker(t, ack)
	logger, _, drain := AppLoggerWithNATS(Config{App: "test"}, NATSConfig{URL: url})
	defer drain()
	for i := range 50 {
		logger.Info("queued", "seq", i)
	}
	done := make(chan struct{})
	go func() { drain(); close(done) }()
	waitLogShutdown(t, ping)
	select {
	case <-done:
		t.Fatal("drain returned before the broker acknowledged the queued logs")
	case <-time.After(20 * time.Millisecond):
	}
	close(ack)
	waitLogShutdown(t, done)
	waitLogShutdown(t, brokerDone)
	seen := make(map[int]bool)
	for body := range messages {
		var entry map[string]any
		if err := json.Unmarshal(body, &entry); err != nil {
			t.Fatal(err)
		}
		if seq, ok := entry["seq"].(float64); ok {
			seen[int(seq)] = true
		}
	}
	if len(seen) != 50 {
		t.Fatalf("drain delivered %d queued logs, want 50", len(seen))
	}
	// Repeated drain and post-shutdown logging must not panic.
	drain()
	logger.Info("after shutdown")
}

func TestAppLoggerWithNATS_DrainForcesCloseAtTimeout(t *testing.T) {
	ack := make(chan struct{})
	url, _, ping, brokerDone := logBroker(t, ack)
	_, _, drain := AppLoggerWithNATS(Config{App: "test"}, NATSConfig{URL: url, DrainTimeout: 200 * time.Millisecond})
	done := make(chan struct{})
	go func() { drain(); close(done) }()
	waitLogShutdown(t, ping)
	waitLogShutdown(t, done) // NATS' own flush timeout is 5s; ours must bound it.
	close(ack)
	waitLogShutdown(t, brokerDone)
}

func TestWithAsyncNats_PreservesSubjectAndFlushes(t *testing.T) {
	ack := make(chan struct{})
	close(ack)
	url, messages, _, brokerDone := logBroker(t, ack)
	nc, err := dialLogNATS(NATSConfig{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	var shipper *asyncNatsWriter
	logger, _ := AppLogger(Config{App: "test", Instance: "host"}, func(cfg Config, ws *[]log.Writer) {
		WithAsyncNats(nc)(cfg, ws)
		shipper = (*ws)[len(*ws)-1].(*asyncNatsWriter)
	})
	nw := shipper.writer.Writer.(*log.IOWriter).Writer.(*NatsWriter)
	if nw.Subject != "app_log.test.host" {
		t.Fatalf("subject = %q", nw.Subject)
	}
	logger.Info("queued")
	if err := shipper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	nc.Close()
	waitLogShutdown(t, brokerDone)
	count := 0
	for range messages {
		count++
	}
	if count != 1 {
		t.Fatalf("delivered %d logs, want 1", count)
	}
}

func TestAsyncNatsWriter_CloseDuringLogging(t *testing.T) {
	shipper := &asyncNatsWriter{writer: &log.AsyncWriter{
		ChannelSize: 200, DiscardOnFull: true, Writer: &log.IOWriter{Writer: io.Discard},
	}}
	logger, _ := AppLogger(Config{App: "test"}, func(_ Config, ws *[]log.Writer) { *ws = append(*ws, shipper) })
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			for range 1000 {
				logger.Info("concurrent")
			}
		})
	}
	close(start)
	if err := shipper.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := shipper.Close(); err != nil {
		t.Fatal(err)
	}
	logger.Info("after shutdown")
}

func TestAppLoggerWithNATS_UnreachableDrainIsConcurrentAndIdempotent(t *testing.T) {
	logger, _, drain := AppLoggerWithNATS(Config{App: "test"}, NATSConfig{URL: "nats://127.0.0.1:1"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(drain)
	}
	wg.Wait()
	logger.Info("after shutdown")
}
