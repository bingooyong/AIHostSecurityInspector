package asset

import "fmt"

type FieldChange struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

type HostChange struct {
	HostID  string        `json:"host_id"`
	Changes []FieldChange `json:"changes"`
}

type GroupChange struct {
	Name    string        `json:"name"`
	Changes []FieldChange `json:"changes"`
}

type Diff struct {
	AddedHosts    []string      `json:"added_hosts"`
	RemovedHosts  []string      `json:"removed_hosts"`
	ChangedHosts  []HostChange  `json:"changed_hosts"`
	AddedGroups   []string      `json:"added_groups"`
	RemovedGroups []string      `json:"removed_groups"`
	ChangedGroups []GroupChange `json:"changed_groups"`
}

func (d Diff) Empty() bool {
	return len(d.AddedHosts) == 0 && len(d.RemovedHosts) == 0 && len(d.ChangedHosts) == 0 && len(d.AddedGroups) == 0 && len(d.RemovedGroups) == 0 && len(d.ChangedGroups) == 0
}

func DiffInventories(oldInv, newInv Inventory) (Diff, error) {
	if err := oldInv.Validate(); err != nil {
		return Diff{}, err
	}
	if err := newInv.Validate(); err != nil {
		return Diff{}, err
	}
	oldHosts := map[string]Host{}
	for _, h := range oldInv.Hosts {
		oldHosts[h.ID] = h
	}
	newHosts := map[string]Host{}
	for _, h := range newInv.Hosts {
		newHosts[h.ID] = h
	}
	var diff Diff
	for id := range newHosts {
		if _, ok := oldHosts[id]; !ok {
			diff.AddedHosts = append(diff.AddedHosts, id)
		}
	}
	for id := range oldHosts {
		if _, ok := newHosts[id]; !ok {
			diff.RemovedHosts = append(diff.RemovedHosts, id)
		}
	}
	for id, oldHost := range oldHosts {
		newHost, ok := newHosts[id]
		if !ok {
			continue
		}
		changes := hostChanges(oldHost, newHost)
		if len(changes) > 0 {
			diff.ChangedHosts = append(diff.ChangedHosts, HostChange{HostID: id, Changes: changes})
		}
	}
	for name := range newInv.Groups {
		if _, ok := oldInv.Groups[name]; !ok {
			diff.AddedGroups = append(diff.AddedGroups, name)
		}
	}
	for name := range oldInv.Groups {
		if _, ok := newInv.Groups[name]; !ok {
			diff.RemovedGroups = append(diff.RemovedGroups, name)
		} else {
			from := fmt.Sprintf("%v", sortedCopy(oldInv.Groups[name].Hosts))
			to := fmt.Sprintf("%v", sortedCopy(newInv.Groups[name].Hosts))
			if from != to {
				diff.ChangedGroups = append(diff.ChangedGroups, GroupChange{Name: name, Changes: []FieldChange{{Field: "hosts", From: from, To: to}}})
			}
		}
	}
	return diff, nil
}

func hostChanges(oldHost, newHost Host) []FieldChange {
	var changes []FieldChange
	add := func(field, from, to string) {
		if from != to {
			changes = append(changes, FieldChange{Field: field, From: from, To: to})
		}
	}
	add("hostname", oldHost.Hostname, newHost.Hostname)
	add("platform", oldHost.Platform, newHost.Platform)
	add("architecture", oldHost.Architecture, newHost.Architecture)
	add("zone", oldHost.Zone, newHost.Zone)
	add("environment", oldHost.Environment, newHost.Environment)
	add("authorized", fmt.Sprintf("%t", IsAuthorized(oldHost)), fmt.Sprintf("%t", IsAuthorized(newHost)))
	add("addresses", fmt.Sprintf("%v", sortedCopy(oldHost.Addresses)), fmt.Sprintf("%v", sortedCopy(newHost.Addresses)))
	add("allowed_profiles", fmt.Sprintf("%v", sortedCopy(oldHost.AllowedProfiles)), fmt.Sprintf("%v", sortedCopy(newHost.AllowedProfiles)))
	add("transport", oldHost.Connection.Transport, newHost.Connection.Transport)
	add("user", oldHost.Connection.User, newHost.Connection.User)
	add("auth_ref", oldHost.Connection.AuthRef, newHost.Connection.AuthRef)
	add("known_hosts_ref", oldHost.Connection.KnownHostsRef, newHost.Connection.KnownHostsRef)
	add("host_key_policy", oldHost.Connection.HostKeyPolicy, newHost.Connection.HostKeyPolicy)
	add("port", fmt.Sprintf("%d", oldHost.Connection.Port), fmt.Sprintf("%d", newHost.Connection.Port))
	return changes
}

func Revalidate(plannedHash string, current Inventory) error {
	hash, err := HashSnapshot(current)
	if err != nil {
		return err
	}
	if hash != plannedHash {
		return fmt.Errorf("asset snapshot drifted")
	}
	return nil
}
