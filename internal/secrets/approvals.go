package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/vault"
)

// Key identifies a request exactly: a remembered approval covers only the
// same harness, host, folder, secrets, variables and command.
func Key(harness string, req Request) string {
	data, _ := json.Marshal([]any{harness, req.Host, req.Dir, req.Uses, req.Argv})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Approvals are remembered "Allow for N min" answers, stored in the
// credential store as one entry per harness: a map from Key to expiry (Unix
// seconds). They hold no secret values.
type Approvals struct {
	Vault   vault.Vault
	Harness string
	Lock    func() (func(), error)
	Now     func() time.Time
}

func (a *Approvals) load() (map[string]int64, error) {
	data, err := a.Vault.Get(a.Harness)
	if err != nil {
		return nil, err
	}
	m := map[string]int64{}
	if data != nil && json.Unmarshal(data, &m) != nil {
		m = map[string]int64{} // a damaged entry approves nothing
	}
	return m, nil
}

// Has reports whether key has an approval that has not expired.
func (a *Approvals) Has(key string) (bool, error) {
	m, err := a.load()
	if err != nil {
		return false, err
	}
	return m[key] > a.Now().Unix(), nil
}

// Add remembers key for d, dropping expired approvals.
func (a *Approvals) Add(key string, d time.Duration) error {
	unlock, err := a.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := a.load()
	if err != nil {
		return err
	}
	now := a.Now().Unix()
	for k, until := range m {
		if until <= now {
			delete(m, k)
		}
	}
	m[key] = now + int64(d/time.Second)
	data, _ := json.Marshal(m)
	return a.Vault.Put(a.Harness, data)
}

// Clear forgets every approval.
func (a *Approvals) Clear() error { return a.Vault.Delete(a.Harness) }

// RulesHash is the SHA-256 of the policy. The rules live in a file the agent
// can edit, so psudo uses them only after the user approves this hash.
func RulesHash(p Policy) string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

const rulesEntry = "rules"

// approvedRules is what the rules entry holds: the hash of the whole policy
// the user approved, and the hash of each of its rules, so that the next
// approval dialog can show only the rules that changed. An entry written by
// an older psudo holds only the policy hash, in hex.
type approvedRules struct {
	Hash  string            `json:"hash"`
	Rules map[string]string `json:"rules"`
}

// ruleHash is the SHA-256 of one rule.
func ruleHash(r Rule) string {
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (a *Approvals) approved() (approvedRules, error) {
	data, err := a.Vault.Get(rulesEntry)
	if err != nil || data == nil {
		return approvedRules{}, err
	}
	var ar approvedRules
	if json.Unmarshal(data, &ar) != nil || ar.Hash == "" {
		return approvedRules{Hash: string(data)}, nil // an older entry
	}
	return ar, nil
}

// RulesApproved reports whether the user approved exactly these rules.
func (a *Approvals) RulesApproved(hash string) (bool, error) {
	ar, err := a.approved()
	return err == nil && ar.Hash != "" && ar.Hash == hash, err
}

// ApprovedRules returns the hash of each rule the user approved last, or nil
// when psudo does not know them (nothing approved yet, or an older entry).
func (a *Approvals) ApprovedRules() (map[string]string, error) {
	ar, err := a.approved()
	return ar.Rules, err
}

// ApproveRules records the user's approval of these rules.
func (a *Approvals) ApproveRules(p Policy) error {
	ar := approvedRules{Hash: RulesHash(p), Rules: map[string]string{}}
	for name, rule := range p {
		ar.Rules[name] = ruleHash(rule)
	}
	data, err := json.Marshal(ar)
	if err != nil {
		return err
	}
	return a.Vault.Put(rulesEntry, data)
}
