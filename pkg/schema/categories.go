package schema

// Claim category enum (spec §5.5). This enum lives in its own file as the
// specification requires (pkg/schema/categories.go). Additions must remain
// backward compatible: unknown categories are accepted on the wire and are
// displayed as misc.other rather than rejected.

// KnownCategories lists the initial claim categories from §5.5.
var KnownCategories = []string{
	"net.fetch",          // external download
	"exec.remote_pipe",   // direct execution of fetched content (curl|sh, eval "$(curl ...)")
	"exec.eval",          // dynamic eval / source usage
	"obfuscation.base64", // base64/hex decode combined with execution
	"fs.delete_broad",    // broad deletion (rm -rf $VAR etc., including expansions)
	"priv.sudo",          // sudo / privilege escalation
	"priv.persist",       // persistence via shell rc, cron, launchd/systemd
	"env.exfil",          // suspected exfiltration of env/credentials
	"pkg.install",        // package-manager execution
	"download.unpinned",  // second-stage fetch without hash/version pinning
	"misc.other",         // everything else (note required)
}

var knownCategorySet = map[string]struct{}{}

func init() {
	for _, c := range KnownCategories {
		knownCategorySet[c] = struct{}{}
	}
}

// DisplayCategory returns the canonical category for display. Unknown values
// are mapped to misc.other.
func DisplayCategory(c string) string {
	if _, ok := knownCategorySet[c]; ok {
		return c
	}
	return "misc.other"
}

// IsKnownCategory reports whether c is one of the known categories.
func IsKnownCategory(c string) bool {
	_, ok := knownCategorySet[c]
	return ok
}
