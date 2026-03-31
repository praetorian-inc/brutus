// Package builtins registers all built-in brutus plugins and analyzers.
// Import this package for its side effects to make all protocols and
// analyzers available via brutus.GetPlugin and brutus.GetAnalyzer.
//
//	import _ "github.com/praetorian-inc/brutus/pkg/builtins"
package builtins

import (
	_ "github.com/praetorian-inc/brutus/internal/analyzers"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins"
	_ "github.com/praetorian-inc/brutus/internal/plugins"
)
