package history

import (
	"sift/audit"
)

type Diff struct {
	New      []audit.Finding `json:"new"`
	Resolved []audit.Finding `json:"resolved"`
	Ongoing  []audit.Finding `json:"ongoing"`
}

func ComputeDiff(previous, current []audit.Finding) Diff {
	prevMap := make(map[string]audit.Finding)
	for _, f := range previous {
		if f.Status == "PASS" {
			continue
		}
		prevMap[diffKey(f)] = f
	}

	currMap := make(map[string]audit.Finding)
	for _, f := range current {
		if f.Status == "PASS" {
			continue
		}
		currMap[diffKey(f)] = f
	}

	var d Diff
	for key, f := range currMap {
		if _, existed := prevMap[key]; existed {
			d.Ongoing = append(d.Ongoing, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for key, f := range prevMap {
		if _, exists := currMap[key]; !exists {
			d.Resolved = append(d.Resolved, f)
		}
	}

	return d
}

func diffKey(f audit.Finding) string {
	return f.Region + "|" + f.Service + "|" + f.ResourceID + "|" + f.Check
}
