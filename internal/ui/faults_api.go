package ui

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/hardw00t/glitchdeck/internal/fault"
)

func (c *control) faults(w http.ResponseWriter, r *http.Request) {
	cfg := c.p.Config()
	respond(w, map[string]any{"schema_version": 2, "seed": cfg.Seed, "seq": c.p.Seq(), "rules": rules(cfg)})
}

func faultSchema(w http.ResponseWriter, r *http.Request) {
	respond(w, map[string]any{"types": fault.Registry})
}

func (c *control) mutateFault(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule fault.Rule
	if r.Method != http.MethodDelete {
		if err := readJSON(w, r, &rule); err != nil {
			faultError(w, r, 400, "invalid_rule", id, "", err)
			return
		}
		if r.Method == http.MethodPost {
			id = rule.ID
		} else if rule.ID != "" && rule.ID != id {
			faultError(w, r, 400, "invalid_rule", id, "", errors.New("rule id must match path"))
			return
		}
		rule.ID = id
	}
	c.cfgMu.Lock()
	cfg := c.p.Config()
	index := slices.IndexFunc(cfg.Rules, func(existing fault.Rule) bool { return existing.ID == id })
	status := http.StatusOK
	switch {
	case r.Method == http.MethodPost && index >= 0:
		c.cfgMu.Unlock()
		faultError(w, r, 409, "duplicate_id", id, "", fmt.Errorf("duplicate rule id %q", id))
		return
	case r.Method == http.MethodPost:
		status = http.StatusCreated
		cfg.Rules = append(cfg.Rules, rule)
	case index < 0:
		c.cfgMu.Unlock()
		faultError(w, r, 404, "not_found", id, "", errRuleNotFound)
		return
	case r.Method == http.MethodDelete:
		cfg.Rules = slices.Delete(cfg.Rules, index, index+1)
	default:
		cfg.Rules[index] = rule
	}
	state, err := c.set(cfg)
	c.cfgMu.Unlock()
	if err != nil {
		invalidFault(w, r, id, err)
		return
	}
	respondStatus(w, status, state)
}

func acceptsJSON(r *http.Request) bool {
	for media := range strings.SplitSeq(r.Header.Get("Accept"), ",") {
		kind, params, err := mime.ParseMediaType(strings.TrimSpace(media))
		if err == nil && kind == "application/json" && params["q"] != "0" {
			return true
		}
	}
	return false
}

func faultError(w http.ResponseWriter, r *http.Request, status int, code, id, param string, err error) {
	if acceptsJSON(r) {
		respondStatus(w, status, map[string]any{"error": map[string]string{
			"code": code, "message": err.Error(), "rule_id": id, "param": param,
		}})
		return
	}
	if status == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	http.Error(w, err.Error(), status)
}

func invalidFault(w http.ResponseWriter, r *http.Request, id string, err error) {
	code, param := "invalid_rule", ""
	var validation *fault.ValidationError
	if errors.As(err, &validation) {
		code, id, param = validation.Code, validation.RuleID, validation.Param
	}
	faultError(w, r, 400, code, id, param, err)
}
