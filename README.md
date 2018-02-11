Auth0 Role Manager [![Build Status](https://travis-ci.org/casbin/auth0-role-manager.svg?branch=master)](https://travis-ci.org/casbin/auth0-role-manager) [![Coverage Status](https://coveralls.io/repos/github/casbin/auth0-role-manager/badge.svg?branch=master)](https://coveralls.io/github/casbin/auth0-role-manager?branch=master) [![Godoc](https://godoc.org/github.com/casbin/auth0-role-manager?status.svg)](https://godoc.org/github.com/casbin/auth0-role-manager)
====

Auth0 Role Manager is the [Auth0](https://auth0.com/) role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load role hierarchy (user-role mapping) from [Auth0 Authorization Extension](https://auth0.com/docs/extensions/authorization-extension/v2) or save role hierarchy to it (NOT Implemented).

## Installation

    go get github.com/casbin/auth0-role-manager

## Simple Example

```go
package main

import (
	"github.com/casbin/auth0-role-manager"
	"github.com/casbin/casbin"
)

func main() {
	// This role manager dose not rely on Casbin policy. So we should not
	// specify grouping policy ("g" policy rules) in the .csv file.
	e := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// Use our role manager.
	// clientID is the Client ID.
	// clientSecret is the Client Secret.
	// tenant is your tenant name. If your domain is: abc.auth0.com, then abc is your tenant name.
	// apiEndpoint is the base URL for your Auth0 Authorization Extension, it should
	// be something like: "https://abc.us.webtask.io/adf6e2f2b84784b57522e3b19dfc9201", there is
	// no "/admins", "/admins/login", "/users" or "/api" in the end.
	rm := auth0rolemanager.NewRoleManager(
		"your_client_id",
		"your_client_secret",
		"your_tenant_name",
		"your_base_url_for_auth0_authorization_extension")
	e.SetRoleManager(rm)

	// If our role manager relies on Casbin policy (like reading "g"
	// policy rules), then we have to set the role manager before loading
	// policy.
	//
	// Otherwise, we can set the role manager at any time, because role
	// manager has nothing to do with the adapter.
	e.LoadPolicy()
	
	// Check the permission.
	// Casbin's subject (user) name uses the Auth0 user's Email field (like "alice@test.com").
	// Casbin's role name uses the Auth0 group's Name field (like "Group1", "Group2").
	e.Enforce("alice@test.com", "data1", "read")
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
