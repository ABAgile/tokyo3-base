package jetstream

import (
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// decodeStub implements the two jetstream.Msg methods decodeMsg calls. The
// embedded nil interface panics on anything else, so the test fails loudly if
// decodeMsg starts depending on more of the message.
type decodeStub struct {
	jetstream.Msg
	meta *jetstream.MsgMetadata
	err  error
	data []byte
}

func (m decodeStub) Metadata() (*jetstream.MsgMetadata, error) { return m.meta, m.err }
func (m decodeStub) Data() []byte                              { return m.data }

func TestDecodeMsg_ReadsSequenceTimeAndData(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	out, err := decodeMsg(decodeStub{
		meta: &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: 42}, Timestamp: ts},
		data: []byte("payload"),
	})
	if err != nil {
		t.Fatalf("decodeMsg: %v", err)
	}
	if out.Seq != 42 || !out.Time.Equal(ts) || string(out.Data) != "payload" {
		t.Fatalf("decodeMsg = %+v", out)
	}
}

// Unreadable metadata surfaces as an error the subscription loop can log,
// rather than a silent skip.
func TestDecodeMsg_UnreadableMetadataIsAnError(t *testing.T) {
	want := errors.New("bad reply subject")
	if _, err := decodeMsg(decodeStub{err: want}); !errors.Is(err, want) {
		t.Fatalf("decodeMsg err = %v, want %v", err, want)
	}
}
