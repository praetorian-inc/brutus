// Package enumplugins imports all enum plugins to auto-register them.
// Each plugin calls enum.Register() in its init() function.
package enumplugins

import (
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/adobe"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/atlassian"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/box"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/dropbox"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/github"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/hubspot"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/linkedin"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/microsoft365"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/okta"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/salesforce"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/slack"
	_ "github.com/praetorian-inc/brutus/internal/enumplugins/zoom"
)
