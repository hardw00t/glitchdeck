//go:build !linux && !windows

package execrun

func subreaper() error    { return nil }
func reapChildren() []int { return nil }
