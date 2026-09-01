package cloudflareprovider

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"time"
)

var (
	ErrScannerOptions = errors.New("Cloudflare scanner options are invalid")
	ErrScannerRunner  = errors.New("Cloudflare scanner runner failed")
)

type ScanRunRequest struct {
	Attempt   int
	ServiceID string
}

// ScanAttemptRunner owns the actual isolated runtime. It must fill observed
// facts and confirm cleanup; Scanner overwrites candidate/service identity so a
// runner cannot accidentally attribute evidence to another request.
type ScanAttemptRunner interface {
	RunScanAttempt(context.Context, WireGuardCandidate, ScanRunRequest) (ScanAttempt, error)
}

type ScanOptions struct {
	Candidate      CandidateOptions
	ServiceID      string
	Attempts       int
	AttemptTimeout time.Duration
	EvidenceTTL    time.Duration
	MaxJitter      time.Duration
}

type Scanner struct {
	Runner ScanAttemptRunner
	Random io.Reader
	Now    func() time.Time
	Wait   func(context.Context, time.Duration) error
}

func normalizeScanOptions(options ScanOptions) (ScanOptions, error) {
	if options.Attempts == 0 {
		options.Attempts = MinScanPasses
	}
	if options.AttemptTimeout == 0 {
		options.AttemptTimeout = 20 * time.Second
	}
	if options.EvidenceTTL == 0 {
		options.EvidenceTTL = 5 * time.Minute
	}
	if options.MaxJitter == 0 {
		options.MaxJitter = 250 * time.Millisecond
	}
	if !validServiceID(options.ServiceID) || options.Attempts < MinScanPasses || options.Attempts > MaxScanAttempts ||
		options.AttemptTimeout < time.Second || options.AttemptTimeout > time.Minute || options.EvidenceTTL < time.Minute || options.EvidenceTTL > 24*time.Hour ||
		options.MaxJitter < 0 || options.MaxJitter > 2*time.Second {
		return ScanOptions{}, ErrScannerOptions
	}
	return options, nil
}

func (scanner Scanner) Scan(ctx context.Context, store *Store, accountID string, options ScanOptions) (ScanReport, error) {
	if store == nil || scanner.Runner == nil {
		return ScanReport{}, ErrScannerOptions
	}
	options, err := normalizeScanOptions(options)
	if err != nil {
		return ScanReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return ScanReport{}, err
	}
	var attempts []ScanAttempt
	err = store.WithWireGuardCandidate(ctx, accountID, options.Candidate, func(ctx context.Context, candidate WireGuardCandidate) error {
		for index := 0; index < options.Attempts; index++ {
			if index > 0 {
				delay, delayErr := scanner.jitter(options.MaxJitter)
				if delayErr != nil {
					return ErrScannerRunner
				}
				if waitErr := scanner.wait(ctx, delay); waitErr != nil {
					return waitErr
				}
			}
			attemptCtx, cancel := context.WithTimeout(ctx, options.AttemptTimeout)
			attempt, runErr := scanner.Runner.RunScanAttempt(attemptCtx, candidate, ScanRunRequest{Attempt: index + 1, ServiceID: options.ServiceID})
			contextErr := attemptCtx.Err()
			cancel()
			attempt.Candidate = candidate.Public()
			attempt.ServiceID = options.ServiceID
			attempts = append(attempts, attempt)
			if contextErr != nil {
				return contextErr
			}
			if runErr != nil {
				return ErrScannerRunner
			}
			if !attempt.CleanupConfirmed {
				break
			}
		}
		return nil
	})
	now := time.Now().UTC()
	if scanner.Now != nil {
		now = scanner.Now().UTC()
	}
	report := EvaluateScanReport(attempts, now, options.EvidenceTTL)
	if err != nil {
		report.Verified = false
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			report.ReasonCode = "scan-canceled"
		case errors.Is(err, ErrScannerRunner):
			report.ReasonCode = "runner-failed"
		default:
			report.ReasonCode = "scan-incomplete"
		}
	}
	return report, err
}

func (scanner Scanner) jitter(maximum time.Duration) (time.Duration, error) {
	if maximum <= 0 {
		return 0, nil
	}
	random := scanner.Random
	if random == nil {
		random = rand.Reader
	}
	value, err := rand.Int(random, big.NewInt(int64(maximum)+1))
	if err != nil {
		return 0, err
	}
	return time.Duration(value.Int64()), nil
}

func (scanner Scanner) wait(ctx context.Context, delay time.Duration) error {
	if scanner.Wait != nil {
		return scanner.Wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
