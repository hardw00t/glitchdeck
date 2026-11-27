package execrun

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type detachedHelper struct {
	reportReader *os.File
	reportWriter *os.File
	ackReader    *os.File
	ackWriter    *os.File
}

func (h *detachedHelper) afterStart() {
	_ = h.reportWriter.Close()
	_ = h.ackReader.Close()
}

func (h *detachedHelper) close() {
	_ = h.reportReader.Close()
	_ = h.reportWriter.Close()
	_ = h.ackReader.Close()
	_ = h.ackWriter.Close()
}

func (h *detachedHelper) readLine(ctx context.Context, output *bufio.Reader) (string, error) {
	stop := context.AfterFunc(ctx, func() { _ = h.reportReader.Close() })
	line, err := output.ReadString('\n')
	if !stop() {
		return "", ctx.Err()
	}
	return line, err
}

func (h *detachedHelper) authorize(ctx context.Context, output *bufio.Reader) error {
	line, err := h.readLine(ctx, output)
	if err != nil {
		return err
	}
	if line != "ready\n" {
		return fmt.Errorf("invalid helper readiness message")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = h.ackWriter.Write([]byte{1})
	_ = h.ackWriter.Close()
	return err
}

func (h *detachedHelper) readPID(ctx context.Context, output *bufio.Reader) (int, error) {
	line, err := h.readLine(ctx, output)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid < 0 {
		return 0, fmt.Errorf("invalid helper PID")
	}
	return pid, nil
}
