package http3

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestResponseBodyReading(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("foobar")))
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
		nil,
	)

	data, err := io.ReadAll(rb)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

func TestResponseBodyReadError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).Return(0, assert.AnError).Times(2)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
		nil,
	)

	_, err := rb.Read([]byte{0})
	require.ErrorIs(t, err, assert.AnError)
	// repeated calls to Read should return the same error
	_, err = rb.Read([]byte{0})
	require.ErrorIs(t, err, assert.AnError)
	select {
	case <-reqDone:
	default:
		t.Fatal("reqDone should be closed")
	}
}

func TestResponseBodyClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).Times(2)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
		nil,
	)
	require.NoError(t, rb.Close())
	select {
	case <-reqDone:
	default:
		t.Fatal("reqDone should be closed")
	}

	// multiple calls to Close should be a no-op
	require.NoError(t, rb.Close())
}

func TestResponseBodyConcurrentClose(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).MaxTimes(3)
	reqDone := make(chan struct{})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		reqDone,
		nil,
	)

	for range 3 {
		go rb.Close()
	}
	select {
	case <-reqDone:
	case <-time.After(time.Second):
		t.Fatal("reqDone should be closed")
	}
}

func TestResponseBodyLengthLimiting(t *testing.T) {
	t.Run("along frame boundary", func(t *testing.T) {
		testResponseBodyLengthLimiting(t, true)
	})

	t.Run("in the middle of a frame", func(t *testing.T) {
		testResponseBodyLengthLimiting(t, false)
	})
}

func testResponseBodyLengthLimiting(t *testing.T, alongFrameBoundary bool) {
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("foo")))
	buf.Write(getDataFrame([]byte("bar")))

	l := int64(4)
	if alongFrameBoundary {
		l = 3
	}
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		l,
		make(chan struct{}),
		nil,
	)
	data, err := io.ReadAll(rb)
	require.Equal(t, []byte("foobar")[:l], data)
	require.ErrorIs(t, err, errTooMuchData)
	// check that repeated calls to Read also return the right error
	n, err := rb.Read([]byte{0})
	require.Zero(t, n)
	require.ErrorIs(t, err, errTooMuchData)
}

func TestResponseBodyContextCancellation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).Return(0, &quic.StreamError{
		StreamID:  42,
		ErrorCode: quic.StreamErrorCode(ErrCodeRequestCanceled),
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		make(chan struct{}),
		ctx,
	)

	_, err := rb.Read([]byte{0})
	require.ErrorIs(t, err, context.Canceled)
}

func TestResponseBodyContextDeadlineExceeded(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).Return(0, &quic.StreamError{
		StreamID:  42,
		ErrorCode: quic.StreamErrorCode(ErrCodeRequestCanceled),
	})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		make(chan struct{}),
		ctx,
	)

	_, err := rb.Read([]byte{0})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestResponseBodyContextCancelledEOFPreserved(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var buf bytes.Buffer
	buf.Write(getDataFrame([]byte("foobar")))
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		make(chan struct{}),
		ctx,
	)

	data, err := io.ReadAll(rb)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
}

func TestResponseBodyNilContext(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := NewMockDatagramStream(mockCtrl)
	str.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	str.EXPECT().Read(gomock.Any()).Return(0, &quic.StreamError{
		StreamID:  42,
		ErrorCode: quic.StreamErrorCode(ErrCodeRequestCanceled),
	})
	rb := newResponseBody(
		newStream(str, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil),
		-1,
		make(chan struct{}),
		nil,
	)

	_, err := rb.Read([]byte{0})
	var h3Err *Error
	require.ErrorAs(t, err, &h3Err)
}
