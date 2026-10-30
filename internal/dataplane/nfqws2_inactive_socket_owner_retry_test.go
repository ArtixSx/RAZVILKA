package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const nfqws2InactiveMissingPeerHeader = "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n"

// Foreign OUTPUT-only queue models, not native evidence or queue exemptions.
func nfqws2InactiveMissingPeerFixture() (BackendInventorySnapshot, []nfqwsScopedQueue, string) {
	image := nfqwsDirectStockQueueFixture()
	for i, family := range []int{4, 6} {
		index := nfqwsDirectStockTestQueueIndex(image, family)
		row := &image.Rows[index]
		row.Tokens[len(row.Tokens)-1] = strconv.Itoa(64511 + i)
	}
	queues := []nfqwsScopedQueue{
		{number: 64511, portID: 99, copyMode: 2, copyRange: 65531},
		{number: 64512, portID: 100, copyMode: 2, copyRange: 65531},
	}
	sockets := nfqws2InactiveMissingPeerHeader + "0 12 99 00000000 0 0 0 0 0 991\n0 12 100 00000000 0 0 0 0 0 1001\n"
	return image, queues, sockets
}

func TestNFQWSInactiveMissingPeerRetriesOnlyWithFreshCompleteFrames(t *testing.T) {
	for _, closing := range []bool{false, true} {
		for _, removed := range []bool{false, true} {
			t.Run(fmt.Sprintf("closing=%t/registration-removed=%t", closing, removed), func(t *testing.T) {
				image, registrations, sockets := nfqws2InactiveMissingPeerFixture()
				before := nfqwsDirectStockTestClone(image)
				transition := 1
				if closing {
					transition = 2
				}
				reads, queueReads, socketReads := 0, 0, 0
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				reader := nfqws2InactiveKernelReader{
					read: func(c context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
						reads++
						if c != ctx || id != image.Scope.Network {
							t.Fatal("observation changed its original context or identity")
						}
						return nfqwsDirectStockTestClone(image), nil
					},
					queues: func(context.Context) ([]nfqwsScopedQueue, error) {
						queueReads++
						if removed && queueReads > transition {
							return nil, nil
						}
						return append([]nfqwsScopedQueue(nil), registrations...), nil
					},
					sockets: func(context.Context) (string, error) {
						socketReads++
						if socketReads == transition {
							return strings.Replace(sockets, "0 12 99 00000000 0 0 0 0 0 991\n", "", 1), nil
						}
						if removed && socketReads > transition {
							return nfqws2InactiveMissingPeerHeader, nil
						}
						return sockets, nil
					},
				}
				if err := reader.check(ctx, image.Scope.Network); err != nil || reads != transition+2 || queueReads != transition+2 || socketReads != transition+2 {
					t.Fatal("transient missing peer was not replaced by a whole complete observation", err, reads, queueReads, socketReads)
				}
				if !reflect.DeepEqual(image, before) {
					t.Fatal("read-only retry changed the foreign queue graph")
				}
			})
		}
	}
}

func TestNFQWSInactiveMissingPeerCannotHideClosingPositiveDrift(t *testing.T) {
	for _, mode := range []string{"port", "mode", "range", "removed", "unknown-later-queue", "duplicate-later-queue", "other-inode"} {
		t.Run(mode, func(t *testing.T) {
			image, registrations, sockets := nfqws2InactiveMissingPeerFixture()
			reads, queueReads, socketReads := 0, 0, 0
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					return nfqwsDirectStockTestClone(image), nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					queueReads++
					q := append([]nfqwsScopedQueue(nil), registrations...)
					if queueReads == 2 {
						switch mode {
						case "port":
							q[0].portID += 2
						case "mode":
							q[0].copyMode--
						case "range":
							q[0].copyRange--
						case "removed":
							q = q[1:]
						case "unknown-later-queue":
							q = append(q, nfqwsScopedQueue{number: 40000, portID: 101, copyMode: 2, copyRange: 65531})
						case "duplicate-later-queue":
							q = append(q, q[1])
						}
					}
					return q, nil
				},
				sockets: func(context.Context) (string, error) {
					socketReads++
					if socketReads == 2 {
						missing := strings.Replace(sockets, "0 12 99 00000000 0 0 0 0 0 991\n", "", 1)
						if mode == "other-inode" {
							missing = strings.Replace(missing, "1001", "1002", 1)
						}
						return missing, nil
					}
					return sockets, nil
				},
			}
			err := reader.check(nfqws2InactiveTestContext(t), image.Scope.Network)
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || reads != 2 || queueReads != 2 || socketReads != 2 {
				t.Fatal("positive drift or another invalid queue was hidden by a missing peer retry", err, reads, queueReads, socketReads)
			}
		})
	}
}

func TestNFQWSInactiveMissingPeerNeedsCompleteTablesAndRemainsBounded(t *testing.T) {
	for _, mode := range []string{"persistent-open", "persistent-close", "wrong-protocol", "zero-inode", "bad-number", "bad-shape", "persistent-duplicate", "mixed-ambiguities", "unknown-later-queue", "read-failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			image, registrations, sockets := nfqws2InactiveMissingPeerFixture()
			reads, queueReads, socketReads := 0, 0, 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					return nfqwsDirectStockTestClone(image), nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) {
					queueReads++
					q := append([]nfqwsScopedQueue(nil), registrations...)
					if mode == "unknown-later-queue" {
						q = append(q, nfqwsScopedQueue{number: 40000, portID: 101, copyMode: 2, copyRange: 65531})
					}
					return q, nil
				},
				sockets: func(context.Context) (string, error) {
					socketReads++
					if mode == "persistent-close" && socketReads%2 == 1 {
						return sockets, nil
					}
					missing := strings.Replace(sockets, "0 12 99 00000000 0 0 0 0 0 991\n", "", 1)
					switch mode {
					case "wrong-protocol":
						return strings.Replace(sockets, "0 12 99 ", "0 15 99 ", 1), nil
					case "zero-inode":
						return strings.Replace(sockets, "991", "0", 1), nil
					case "bad-number":
						return missing + "0 12 101 00000000 0 0 0 0 0 010\n", nil
					case "bad-shape":
						return missing + "private malformed row\n", nil
					case "persistent-duplicate":
						return missing + "0 12 100 00000000 0 0 0 0 0 1002\n", nil
					case "mixed-ambiguities":
						if socketReads == 1 {
							return missing + "0 12 100 00000000 0 0 0 0 0 1002\n", nil
						}
					case "read-failure":
						return missing, errors.New("private source error")
					case "cancel":
						cancel()
					}
					return missing, nil
				},
			}
			err := reader.check(ctx, image.Scope.Network)
			want := 1
			switch mode {
			case "persistent-open", "wrong-protocol", "persistent-duplicate", "mixed-ambiguities":
				want = 3
			case "persistent-close":
				want = 6
			}
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || reads != want || queueReads != want || socketReads != want {
				t.Fatal("missing, malformed, ambiguous, or canceled ownership became absence or escaped its retry bound", err, reads, queueReads, socketReads)
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation was lost", err)
			}
		})
	}
}

func TestNFQWSInactiveMissingPeerRetryCannotHideFreshSourceRefusal(t *testing.T) {
	for _, mode := range []string{"source", "identity", "graph", "changed-fresh-inode"} {
		t.Run(mode, func(t *testing.T) {
			image, registrations, sockets := nfqws2InactiveMissingPeerFixture()
			reads, socketReads := 0, 0
			reader := nfqws2InactiveKernelReader{
				read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
					reads++
					value := nfqwsDirectStockTestClone(image)
					if reads > 1 {
						switch mode {
						case "source":
							return value, errors.New("private source error")
						case "identity":
							value.Scope.Network.Inode++
						case "graph":
							value.Rows = append(value.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "RZQ_unknown"))
						}
					}
					return value, nil
				},
				queues: func(context.Context) ([]nfqwsScopedQueue, error) { return registrations, nil },
				sockets: func(context.Context) (string, error) {
					socketReads++
					if socketReads == 1 {
						return nfqws2InactiveMissingPeerHeader, nil
					}
					if mode == "changed-fresh-inode" && socketReads == 3 {
						return strings.Replace(sockets, "991", "992", 1), nil
					}
					return sockets, nil
				},
			}
			err := reader.check(nfqws2InactiveTestContext(t), image.Scope.Network)
			wantReads, wantSockets := 2, 1
			if mode == "changed-fresh-inode" {
				wantReads, wantSockets = 3, 3
			}
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || reads != wantReads || socketReads != wantSockets {
				t.Fatal("fresh complete source was not required after missing peer", err, reads, socketReads)
			}
		})
	}
}

func TestNFQWSInactiveMissingPeerDoesNotAuthorizeGenericOrCompoundRetry(t *testing.T) {
	missing := nfqws2InactiveKernelAt("socket.owner", errors.Join(ErrNFQWSManagedKernelOwner, ErrNFQWSScopedOwner, errNFQWS2InactiveSocketPeerMissing))
	closing := nfqws2InactiveKernelAt("frame.changed", errors.Join(ErrNFQWSManagedKernelOwner, missing))
	if !nfqws2InactiveMissingPeerRead(missing) || !nfqws2InactiveMissingPeerRead(closing) {
		t.Fatal("canonical private missing-peer branch refused a fresh observation")
	}
	duplicate := nfqws2InactiveKernelAt("socket.table", nfqws2InactiveKernelAt("socket.table.duplicate", ErrNFQWSManagedKernelOwner))
	for _, err := range []error{
		nfqws2InactiveKernelAt("socket.owner", errors.Join(ErrNFQWSManagedKernelOwner, ErrNFQWSScopedOwner)),
		errors.New(missing.Error()), errNFQWS2InactiveSocketPeerMissing,
		errors.Join(missing, context.Canceled), errors.Join(missing, errors.New("other private refusal")),
		errors.Join(missing, ErrNFQWSManagedKernelOwner), errors.Join(missing, ErrNFQWSScopedOwner),
		nfqws2InactiveKernelAt("socket.owner", errors.Join(ErrNFQWSManagedKernelOwner, ErrNFQWSScopedOwner, errNFQWS2InactiveSocketPeerMissing, ErrNFQWSManagedKernelOwner)),
		nfqws2InactiveKernelAt("socket.owner", errors.Join(ErrNFQWSManagedKernelOwner, ErrNFQWSScopedOwner, errNFQWS2InactiveSocketPeerMissing, ErrNFQWSScopedOwner)),
		nfqws2InactiveKernelAt("frame.changed", errors.Join(ErrNFQWSManagedKernelOwner, closing)),
		errors.Join(missing, nfqws2InactiveKernelAt("frame.changed", ErrNFQWSManagedKernelOwner)),
		errors.Join(missing, duplicate), errors.Join(missing, missing),
		nfqws2InactiveKernelAt("socket.inventory", missing), fmt.Errorf("foreign wrapper: %w", missing),
	} {
		if nfqws2InactiveMissingPeerRead(err) {
			t.Fatal("generic or compound refusal became retry authority", err)
		}
	}
}

func TestNFQWSInactiveMissingPeerRetryStillRequiresOuterBookends(t *testing.T) {
	for _, mode := range []string{"unchanged", "file", "process", "source"} {
		t.Run(mode, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			image, registrations, sockets := nfqws2InactiveMissingPeerFixture()
			f.image = image
			socketReads := 0
			f.proof.queues = func(context.Context) ([]nfqwsScopedQueue, error) { return registrations, nil }
			f.proof.sockets = func(context.Context) (string, error) {
				socketReads++
				if socketReads == 1 {
					return nfqws2InactiveMissingPeerHeader, nil
				}
				if socketReads == 2 {
					switch mode {
					case "file":
						if err := os.WriteFile(f.a.ConfigPath, []byte("# changed during retry\n"), 0600); err != nil {
							t.Fatal(err)
						}
					case "process":
						f.process(t, 2, "nfqws2", 'S', 0, "nfqws2\x00")
					case "source":
						f.source.inventory.review = strings.Repeat("d", 64)
					}
				}
				return sockets, nil
			}
			err := f.verify(nfqws2InactiveTestContext(t))
			if (mode == "unchanged") != (err == nil) || f.uses != 1 || f.reads != 3 || socketReads != 3 {
				t.Fatal("kernel retry replaced the original lease or bypassed closing process/file/source checks", err, f.uses, f.reads, socketReads)
			}
		})
	}
}

func TestNFQWSInactiveMissingPeerRetryPreservesForeignSharedPeerAndUnrelatedChurn(t *testing.T) {
	image, registrations, _ := nfqws2InactiveMissingPeerFixture()
	registrations[1].portID = registrations[0].portID
	reads, socketReads := 0, 0
	reader := nfqws2InactiveKernelReader{
		read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			return nfqwsDirectStockTestClone(image), nil
		},
		queues: func(context.Context) ([]nfqwsScopedQueue, error) { return registrations, nil },
		sockets: func(context.Context) (string, error) {
			socketReads++
			return nfqws2InactiveMissingPeerHeader + fmt.Sprintf("0 12 99 00000000 %d 0 0 0 0 991\n0 15 101 00000000 0 0 0 0 0 %d\n", socketReads, 1000+socketReads), nil
		},
	}
	if err := reader.check(nfqws2InactiveTestContext(t), image.Scope.Network); err != nil || reads != 2 || socketReads != 2 {
		t.Fatal("unchanged foreign queues 64511/64512 or unrelated socket churn needed a retry", err, reads, socketReads)
	}
}

func TestNFQWSInactiveMissingPeerRetryHonorsOriginalDeadline(t *testing.T) {
	image, registrations, _ := nfqws2InactiveMissingPeerFixture()
	reads := 0
	reader := nfqws2InactiveKernelReader{
		read: func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error) {
			reads++
			return image, nil
		},
		queues:  func(context.Context) ([]nfqwsScopedQueue, error) { return registrations, nil },
		sockets: func(context.Context) (string, error) { return nfqws2InactiveMissingPeerHeader, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := reader.check(ctx, image.Scope.Network)
	if !errors.Is(err, ErrNFQWSManagedKernelOwner) || !errors.Is(err, context.DeadlineExceeded) || reads > 1 {
		t.Fatal("missing peer retry replaced or outlived the caller deadline", err, reads)
	}
}
