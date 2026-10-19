package approval

import (
	"slices"
	"time"
)

// Draft is a persistence representation, never an authorization grant from a client.
// Restore validates it through New and replays every vote through the domain rules.
type Draft struct {
	ID        string    `json:"id"`
	Applicant string    `json:"applicant"`
	Operation Operation `json:"operation"`
	Policy    Policy    `json:"policy"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
}

func (r Request) Draft() Draft {
	policy := r.policy
	policy.Approvers = slices.Clone(policy.Approvers)
	return Draft{r.id, r.applicant, r.Operation(), policy, r.created, r.expires}
}

// RestoreVotes supports persisted approval decisions only. Execution state must
// later be recovered from its own transactional journal, not guessed from votes.
func RestoreVotes(d Draft, votes []Vote) (Request, error) {
	r, err := New(d.ID, d.Applicant, d.Operation, d.Policy, d.Created, d.Expires)
	if err != nil {
		return Request{}, err
	}
	last := d.Created
	for _, v := range votes {
		if v.At.Before(last) {
			return Request{}, ErrInvalid
		}
		r, err = r.Vote(v.Actor, v.Accept, v.At)
		if err != nil {
			return Request{}, err
		}
		last = v.At
	}
	return r, nil
}
