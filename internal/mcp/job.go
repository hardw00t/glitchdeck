package mcp

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"time"
)

const execGrace = 2 * time.Second

type jobRun func(context.Context) map[string]any

type job struct {
	id       string
	cancel   context.CancelFunc
	done     chan struct{}
	finished bool
}

func jobID(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}
	if id[0] == '"' {
		var text string
		_ = json.Unmarshal(id, &text)
		return strconv.Quote(text)
	}
	n, _ := strconv.ParseInt(string(id), 10, 64)
	return strconv.FormatInt(n, 10)
}

func (s *Server) cancelJob(raw json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.RequestID) == 0 || !validID(p.RequestID) {
		return
	}
	id := jobID(p.RequestID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != nil && !s.job.finished && id == s.job.id {
		s.job.cancel()
	}
}

func (s *Server) runningJob() *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.job
}

func (s *Server) busyJob() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != nil {
		return s.job.id, true
	}
	return "", false
}

func (s *Server) startJob(id json.RawMessage, name string, run jobRun, write func(any)) <-chan struct{} {
	ctx, cancel := context.WithCancel(s.ctx)
	j := &job{id: jobID(id), cancel: cancel, done: make(chan struct{})}
	s.mu.Lock()
	s.job = j
	s.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			if s.job == j {
				s.job = nil
			}
			close(j.done)
			s.mu.Unlock()
		}()
		response := runJob(ctx, id, name, run)
		s.mu.Lock()
		cancelled := ctx.Err() != nil
		j.finished = true
		s.mu.Unlock()
		if cancelled {
			log.Printf("%s cancelled: request %s", name, j.id)
		} else if len(id) != 0 {
			write(response)
		}
	}()
	return j.done
}

func runJob(ctx context.Context, id json.RawMessage, name string, run jobRun) (response map[string]any) {
	defer func() {
		if recover() != nil {
			response = rpcError(id, -32603, "Internal error", nil)
		}
	}()
	return toolResponse(id, name, run(ctx))
}

func (s *Server) shutdownJob() {
	j := s.runningJob()
	if j == nil {
		return
	}
	j.cancel()
	timer := time.NewTimer(3*execGrace + 8*time.Second)
	defer timer.Stop()
	select {
	case <-j.done:
	case <-timer.C:
		log.Print("exec_run: child cleanup did not finish")
	}
}
