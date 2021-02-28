package misc

import "time"

// Benchmark benchmarking struct. Example:
// b := Benchmark{}
// b.Start()
// ...
// bench := b.Stop()
type Benchmark struct {
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Duration     string    `json:"duration"`
	DurationNano int64     `json:"duration_nano"`
	DurationSec  float64   `json:"duration_sec"`
	Msg          string    `json:"msg"`
}

// Start start benchmarking time
func (t *Benchmark) Start() {
	t.StartTime = time.Now()
}

// Stop stop benchmarking
func (t *Benchmark) Stop(msg ...string) *Benchmark {
	duration := time.Since(t.StartTime)
	t.EndTime = time.Now()
	t.Duration = duration.String()
	t.DurationNano = duration.Nanoseconds()
	t.DurationSec = duration.Seconds()
	if len(msg) > 0 {
		t.Msg = msg[0]
	}
	return t
}
