package score

// Scoring parameters. These are versioned and intentionally conservative.
const (
	ParamsVersion = "v0.1.0"

	TrustDefault = 0.01

	PositiveMultiplierBase       = 1.0
	FamilyDiversityBonusPerExtra = 0.2
	FamilyDiversityBonusMax      = 2.0

	NegativeMultiplier = 3.0

	TrustedPositiveThreshold = 1.0

	DeltaInheritanceCoefficient = 0.5
	DeltaMaxDepth               = 3
)

// Severity assigns a weight to each claim category. Unknown values are
// normalized to misc.other before lookup.
var Severity = map[string]float64{
	"net.fetch":          0.5,
	"exec.remote_pipe":   1.0,
	"exec.eval":          1.0,
	"obfuscation.base64": 0.8,
	"fs.delete_broad":    0.7,
	"priv.sudo":          0.6,
	"priv.persist":       0.9,
	"env.exfil":          0.8,
	"pkg.install":        0.5,
	"download.unpinned":  0.3,
	"misc.other":         0.4,
}
