package server

import (
	"github.com/KamorionLabs/dns-gate/internal/glob"
	"github.com/KamorionLabs/dns-gate/internal/policy"
	"github.com/KamorionLabs/dns-gate/internal/uiapi"
)

// readableZones keeps the zone summaries the caller can read, with the
// provider folder of each, and, when folder is a folder glob, only the zones
// whose folder matches it.
func readableZones(snap *policy.Snapshot, zs []uiapi.ZoneSummary, readable map[string]bool, folder string) []uiapi.ZoneSummary {
	out := make([]uiapi.ZoneSummary, 0, len(zs))
	for _, z := range zs {
		if !readable[z.Zone] {
			continue
		}
		z.Folder = snap.Folder(z.Zone)
		if folder != "" && !glob.MatchFolder(folder, z.Folder) {
			continue
		}
		out = append(out, z)
	}
	return out
}
