package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"time"
)

// One full-group call owns one fresh image and one work buffer: less than
// 64 MiB total. Larger images keep the original bounded streaming SHA path.
// No role, process fact or successful observation is retained here.
const ordinaryImageRetainLimit = 63 << 20
const ordinaryImageChunk = 128 << 10

type ordinaryExecutableImage struct {
	self     *ordinaryExecutableImage
	original context.Context
	deadline time.Time
	digest   string
	image    []byte
	work     [ordinaryImageChunk]byte
	closed   bool
}

func newOrdinaryExecutableImage(ctx context.Context, digest string) (*ordinaryExecutableImage, error) {
	if ctx == nil || !validDigest("sha256:"+digest) {
		return nil, ErrFileProtocol
	}
	deadline, finite := ctx.Deadline()
	if !finite || ctx.Err() != nil || !deadline.After(time.Now()) {
		return nil, errors.Join(ErrFileProtocol, ctx.Err())
	}
	r := &ordinaryExecutableImage{original: ctx, deadline: deadline, digest: digest}
	r.self = r
	return r, nil
}

func (r *ordinaryExecutableImage) current() error {
	if r == nil || r.self != r || r.closed || r.original == nil {
		return ErrFileProtocol
	}
	if err := r.original.Err(); err != nil {
		return errors.Join(ErrFileProtocol, err)
	}
	if !r.deadline.After(time.Now()) {
		return errors.Join(ErrFileProtocol, context.DeadlineExceeded)
	}
	return nil
}

func (r *ordinaryExecutableImage) clear() {
	if r == nil || r.self != r {
		return
	}
	clear(r.image)
	r.image = nil
	clear(r.work[:])
	r.closed = true
	r.original = nil
	r.digest = ""
}

// verify always reads the entire actual executable occurrence, including EOF.
// Equality to a privately owned freshly SHA-authenticated image verifies the
// same digest without hashing identical bytes again. Changed bytes, read
// failures and cancellation poison this call's image; nothing survives exit.
func (r *ordinaryExecutableImage) verify(source io.Reader, size int64) (digest string, result error) {
	defer func() {
		if result != nil {
			r.clear()
		}
	}()
	if err := r.current(); err != nil {
		return "", err
	}
	if source == nil || size < 0 || size > MaximumBinaryBytes {
		return "", ErrFileProtocol
	}
	var capture []byte
	if r.image == nil && size <= ordinaryImageRetainLimit {
		capture = make([]byte, int(size))
		defer func() { clear(capture) }()
	}
	var streamed hash.Hash
	if r.image == nil && capture == nil {
		streamed = sha256.New()
	}
	limited := &io.LimitedReader{R: source, N: MaximumBinaryBytes + 1}
	total, equal := int64(0), true
	for {
		if err := r.current(); err != nil {
			return "", err
		}
		n, err := limited.Read(r.work[:])
		if contextErr := r.current(); contextErr != nil {
			return "", contextErr
		}
		if n > 0 {
			end := total + int64(n)
			if end > MaximumBinaryBytes {
				return "", ErrFileProtocol
			}
			if r.image != nil {
				if end > int64(len(r.image)) || !bytes.Equal(r.work[:n], r.image[total:end]) {
					equal = false
				}
			} else if capture != nil {
				if end > int64(len(capture)) {
					equal = false
				} else {
					copy(capture[total:end], r.work[:n])
				}
			} else {
				_, _ = streamed.Write(r.work[:n])
			}
			total = end
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return "", errors.Join(ErrFileProtocol, err)
			}
			break
		}
		if n == 0 {
			return "", errors.Join(ErrFileProtocol, io.ErrNoProgress)
		}
	}
	if total != size || !equal || r.image != nil && total != int64(len(r.image)) {
		return "", ErrFileProtocol
	}
	if capture != nil {
		sum := sha256.Sum256(capture)
		if hex.EncodeToString(sum[:]) != r.digest {
			return "", ErrFileProtocol
		}
	} else if streamed != nil && hex.EncodeToString(streamed.Sum(nil)) != r.digest {
		return "", ErrFileProtocol
	}
	if err := r.current(); err != nil {
		return "", err
	}
	if capture != nil {
		r.image = capture
		capture = nil // The sole original owner now clears these bytes on exit.
	}
	return r.digest, nil
}
