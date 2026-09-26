module example.com/app

go 1.23

require github.com/old/thing v1.0.0

// The module that actually gets built is the replacement, so its licence is the
// one that governs. See internal/parsers/gomod.go.
replace github.com/old/thing => github.com/new/thing v2.0.0
