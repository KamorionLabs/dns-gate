package glob

import (
	"errors"
	"strings"
)

// RootFolder is the folder of the zones that are in no folder.
const RootFolder = "/"

// NormalizeFolder returns the canonical form of a provider folder path: a
// leading "/", no trailing "/", and "/" for the root (an empty path).
func NormalizeFolder(path string) string {
	p := strings.TrimSpace(path)
	p = strings.Trim(p, "/")
	if p == "" {
		return RootFolder
	}
	return "/" + p
}

// MatchFolder reports whether a folder path ("/" for the root, "/ES/Sub")
// matches a folder pattern with the segments of host patterns: "*" matches
// exactly one segment, "**" one or more segments, and "*" inside a segment
// any run of characters. "/" matches only the root, "/ES" only the folder
// ES, "/ES/**" every folder below it. Matching is case-sensitive. An empty
// folder (a zone without folders) never matches.
func MatchFolder(pattern, folder string) bool {
	if folder == "" || pattern == "" {
		return false
	}
	if pattern == RootFolder || folder == RootFolder {
		return pattern == folder
	}
	return matchLabels(segments(pattern), segments(folder))
}

// AnyFolder reports whether folder matches at least one pattern.
func AnyFolder(patterns []string, folder string) bool {
	for _, p := range patterns {
		if MatchFolder(p, folder) {
			return true
		}
	}
	return false
}

// FolderCovered reports whether every folder matched by the folder pattern p
// is matched by one of the allowed patterns. It is conservative: it may
// refuse a pattern that is in fact covered, never the reverse.
func FolderCovered(allowed []string, p string) bool {
	if ValidFolderPattern(p) != nil {
		return false
	}
	for _, a := range allowed {
		switch {
		case ValidFolderPattern(a) != nil:
			continue
		case a == RootFolder || p == RootFolder:
			if a == p {
				return true
			}
			continue
		}
		if segmentsCovered(segments(a), segments(p)) {
			return true
		}
	}
	return false
}

func segmentsCovered(a, p []string) bool {
	if len(a) == 0 {
		return len(p) == 0
	}
	if a[0] == "**" {
		for i := 1; i <= len(p); i++ {
			if segmentsCovered(a[1:], p[i:]) {
				return true
			}
		}
		return false
	}
	if len(p) == 0 || p[0] == "**" || !Match(a[0], p[0]) {
		return false
	}
	return segmentsCovered(a[1:], p[1:])
}

// ValidFolderPattern checks a folder pattern: "/" or "/" followed by
// non-empty segments separated by "/", without "?", "**" only as a whole
// segment.
func ValidFolderPattern(p string) error {
	switch {
	case p == RootFolder:
		return nil
	case !strings.HasPrefix(p, "/"):
		return errors.New("must start with /")
	case strings.HasSuffix(p, "/"):
		return errors.New("must not end with /")
	case len(p) > 512:
		return errors.New("at most 512 characters")
	case strings.Contains(p, "?"):
		return errors.New("only * and ** wildcards are supported")
	}
	for _, s := range segments(p) {
		switch {
		case strings.TrimSpace(s) == "":
			return errors.New("empty folder segment")
		case strings.Contains(s, "**") && s != "**":
			return errors.New("** must be a whole segment")
		case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return errors.New("control character")
		}
	}
	return nil
}

func segments(p string) []string { return strings.Split(strings.TrimPrefix(p, "/"), "/") }
