//go:build linux

package nativecheckfixture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// ResourceUsage describes an observed fixture window, not a router budget.
// Self CPU includes the fixture TLS/DNS servers and this sampler. Children CPU
// comes from RUSAGE_CHILDREN: only children reaped during the window contribute.
// RSS is an absolute peak of observed samples; short-lived children can be missed.
type ResourceUsage struct {
	SelfUserMS, SelfSystemMS, JoinedChildrenUserMS, JoinedChildrenSystemMS float64
	SelfPeakRSSKiB, NewChildrenPeakRSSKiB                                  int64
	SelfRSSSamples, ChildrenRSSSamples, ReadErrors                         int
	Interval                                                               time.Duration
}

var ResourceCSVHeaders = []string{"resource_schema", "cpu_self_user_ms", "cpu_self_system_ms", "cpu_joined_children_user_ms", "cpu_joined_children_system_ms", "observed_self_peak_rss_kib", "observed_new_children_peak_rss_kib", "self_rss_samples", "new_children_rss_samples", "rss_read_errors", "sampler_interval_ms"}

func (u ResourceUsage) CSV() []string {
	children := ""
	if u.ChildrenRSSSamples > 0 {
		children = strconv.FormatInt(u.NewChildrenPeakRSSKiB, 10)
	}
	return []string{"linux-rusage-observed-rss-v1", fmt.Sprintf("%.3f", u.SelfUserMS), fmt.Sprintf("%.3f", u.SelfSystemMS), fmt.Sprintf("%.3f", u.JoinedChildrenUserMS), fmt.Sprintf("%.3f", u.JoinedChildrenSystemMS), strconv.FormatInt(u.SelfPeakRSSKiB, 10), children, strconv.Itoa(u.SelfRSSSamples), strconv.Itoa(u.ChildrenRSSSamples), strconv.Itoa(u.ReadErrors), strconv.FormatInt(u.Interval.Milliseconds(), 10)}
}

type ResourceSample struct {
	beforeSelf, beforeChildren unix.Rusage
	baseline                   map[int]string
	stop, done                 chan struct{}
	once                       sync.Once
	usage                      ResourceUsage // sampler writer; read only after done is joined
	result                     ResourceUsage
	err                        error
}

// StartResourceSample observes only /proc and getrusage. It never signals,
// adopts or authorizes a process. Every preexisting direct-child subtree is
// excluded, including fixture peers and any later descendants of those peers.
func StartResourceSample() (*ResourceSample, error) {
	r := &ResourceSample{stop: make(chan struct{}), done: make(chan struct{}), baseline: map[int]string{}, usage: ResourceUsage{Interval: 10 * time.Millisecond}}
	if err := unix.Getrusage(unix.RUSAGE_SELF, &r.beforeSelf); err != nil {
		return nil, err
	}
	if err := unix.Getrusage(unix.RUSAGE_CHILDREN, &r.beforeChildren); err != nil {
		return nil, err
	}
	children, err := directChildren(os.Getpid())
	if err != nil {
		return nil, err
	}
	for _, pid := range children {
		birth, _, err := processRSS(pid)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		r.baseline[pid] = birth
	}
	r.sample()
	if r.usage.SelfRSSSamples == 0 {
		return nil, errors.New("parent RSS observation unavailable")
	}
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.usage.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				r.sample()
				return
			case <-ticker.C:
				r.sample()
			}
		}
	}()
	return r, nil
}

// Stop is idempotent and joins the bounded sampler before reading its data.
// Call only after the actual checker/queue has joined its native children.
func (r *ResourceSample) Stop() (ResourceUsage, error) {
	if r == nil {
		return ResourceUsage{}, errors.New("resource sample missing")
	}
	r.once.Do(func() {
		close(r.stop)
		<-r.done
		var self, children unix.Rusage
		r.err = errors.Join(unix.Getrusage(unix.RUSAGE_SELF, &self), unix.Getrusage(unix.RUSAGE_CHILDREN, &children))
		r.result = r.usage
		r.result.SelfUserMS = timevalMS(self.Utime) - timevalMS(r.beforeSelf.Utime)
		r.result.SelfSystemMS = timevalMS(self.Stime) - timevalMS(r.beforeSelf.Stime)
		r.result.JoinedChildrenUserMS = timevalMS(children.Utime) - timevalMS(r.beforeChildren.Utime)
		r.result.JoinedChildrenSystemMS = timevalMS(children.Stime) - timevalMS(r.beforeChildren.Stime)
		if r.result.SelfUserMS < 0 || r.result.SelfSystemMS < 0 || r.result.JoinedChildrenUserMS < 0 || r.result.JoinedChildrenSystemMS < 0 {
			r.err = errors.Join(r.err, errors.New("rusage counter regressed"))
		}
	})
	return r.result, r.err
}

func timevalMS(t unix.Timeval) float64 { return float64(t.Sec)*1000 + float64(t.Usec)/1000 }

func (r *ResourceSample) sample() {
	_, self, err := processRSS(os.Getpid())
	if err != nil {
		r.usage.ReadErrors++
	} else {
		r.usage.SelfRSSSamples++
		r.usage.SelfPeakRSSKiB = max(r.usage.SelfPeakRSSKiB, self)
	}
	roots, err := directChildren(os.Getpid())
	if err != nil {
		r.usage.ReadErrors++
		return
	}
	var sum int64
	observed := false
	seen := map[int]bool{}
	for _, pid := range roots {
		birth, _, err := processRSS(pid)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				r.usage.ReadErrors++
			}
			continue
		}
		if r.baseline[pid] == birth {
			continue
		}
		amount, count, err := descendantRSS(pid, os.Getpid(), seen, 0)
		if err != nil {
			r.usage.ReadErrors++
		}
		sum += amount
		observed = observed || count > 0
	}
	if observed {
		r.usage.ChildrenRSSSamples++
		r.usage.NewChildrenPeakRSSKiB = max(r.usage.NewChildrenPeakRSSKiB, sum)
	}
}

func descendantRSS(pid, parent int, seen map[int]bool, depth int) (int64, int, error) {
	if depth > 16 || len(seen) >= 256 {
		return 0, 0, errors.New("fixture child tree exceeds bound")
	}
	if seen[pid] {
		return 0, 0, nil
	}
	seen[pid] = true
	birth, actualParent, rss, err := processRSSParent(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	if actualParent != parent {
		return 0, 0, nil
	} // PID reuse cannot add an unrelated process.
	children, err := directChildren(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	count := 1
	for _, child := range children {
		amount, n, e := descendantRSS(child, pid, seen, depth+1)
		rss += amount
		count += n
		err = errors.Join(err, e)
	}
	closing, _, closeErr := processRSS(pid)
	if closeErr != nil || closing != birth {
		if errors.Is(closeErr, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, errors.Join(closeErr, errors.New("sampled process birth changed"))
	}
	return rss, count, err
}

func directChildren(pid int) ([]int, error) {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	if len(tasks) > 4096 {
		return nil, errors.New("fixture task inventory exceeds bound")
	}
	unique := map[int]bool{}
	for _, task := range tasks {
		data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", task.Name(), "children"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(data) > 64<<10 {
			return nil, errors.New("fixture children inventory exceeds bound")
		}
		for _, raw := range strings.Fields(string(data)) {
			child, err := strconv.Atoi(raw)
			if err != nil || child < 1 {
				return nil, errors.New("invalid fixture child PID")
			}
			unique[child] = true
			if len(unique) > 256 {
				return nil, errors.New("fixture child inventory exceeds bound")
			}
		}
	}
	result := make([]int, 0, len(unique))
	for pid := range unique {
		result = append(result, pid)
	}
	return result, nil
}

func processRSS(pid int) (string, int64, error) {
	birth, _, rss, err := processRSSParent(pid)
	return birth, rss, err
}

func processRSSParent(pid int) (string, int, int64, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return "", 0, 0, err
	}
	if len(stat) > 16<<10 {
		return "", 0, 0, errors.New("fixture proc stat exceeds bound")
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return "", 0, 0, errors.New("invalid fixture proc stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return "", 0, 0, errors.New("incomplete fixture proc stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", 0, 0, errors.New("invalid fixture process birth")
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent < 0 {
		return "", 0, 0, errors.New("invalid fixture parent")
	}
	data, err := os.ReadFile(filepath.Join(base, "statm"))
	if err != nil {
		return "", 0, 0, err
	}
	pages := strings.Fields(string(data))
	if len(pages) < 2 {
		return "", 0, 0, errors.New("invalid fixture statm")
	}
	resident, err := strconv.ParseInt(pages[1], 10, 64)
	if err != nil || resident < 0 {
		return "", 0, 0, errors.New("invalid fixture RSS")
	}
	return fields[19], parent, resident * int64(os.Getpagesize()) / 1024, nil
}
