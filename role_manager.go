// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth0rolemanager

import (
	"errors"
	"fmt"

	"github.com/casbin/casbin/rbac"
	"github.com/casbin/casbin/util"
	"github.com/zenoss/go-auth0/auth0"
)

type RoleManager struct {
	clientID     string
	clientSecret string
	audience     string
	tenant       string
	apiEndpoint  string

	nameToIDMap  map[string]string
	idToNameMap  map[string]string

	mgmtClient   *auth0.Auth0
	authzClient   *auth0.Auth0
}

// NewRoleManager is the constructor of an Auth0 RoleManager instance.
// clientID is the Client ID.
// clientSecret is the Client Secret.
// tenant is your tenant name. If your domain is: abc.auth0.com, then abc is your tenant name.
// apiEndpoint is the base URL for your Auth0 Authorization Extension, it should
// be something like: "https://abc.us.webtask.io/adf6e2f2b84784b57522e3b19dfc9201", there is
// no "/admins", "/admins/login", "/users" or "/api" in the end.
func NewRoleManager(clientID string, clientSecret string, tenant string, apiEndpoint string) rbac.RoleManager {
	rm := RoleManager{}
	rm.clientID = clientID
	rm.clientSecret = clientSecret
	rm.tenant = tenant
	rm.apiEndpoint = apiEndpoint

	rm.nameToIDMap = map[string]string{}
	rm.idToNameMap = map[string]string{}

	rm.initialize()
	rm.loadMapping()

	return &rm
}

func (rm *RoleManager) initialize() error {
	cfg := auth0.Config{
		ClientID:         rm.clientID,
		ClientSecret:     rm.clientSecret,
		Tenant:           rm.tenant,
		AuthorizationURL: rm.apiEndpoint,
	}

	var err error

	rm.mgmtClient, err = cfg.ClientFromCredentials(fmt.Sprintf("https://%s.auth0.com/api/v2/", rm.tenant))
	if err != nil {
		return err
	}

	rm.authzClient, err = cfg.ClientFromCredentials("urn:auth0-authz-api")
	if err != nil {
		return err
	}

	return nil
}

func (rm *RoleManager) loadMapping() {
	util.LogPrintf("Loading (ID, name) mapping for users:")
	users, _ := rm.mgmtClient.Mgmt.Users.GetAll()
	for _, user := range users {
		rm.nameToIDMap[user.Email] = user.ID
		rm.idToNameMap[user.ID] = user.Email
		util.LogPrintf("%s -> %s", user.ID, user.Email)
	}

	util.LogPrintf("Loading (ID, name) mapping for groups:")
	groups, _ := rm.authzClient.Authz.Groups.GetAll()
	for _, group := range groups {
		rm.nameToIDMap[group.Name] = group.ID
		rm.idToNameMap[group.ID] = group.Name
		util.LogPrintf("%s -> %s", group.ID, group.Name)
	}
}

func (rm *RoleManager) getAuth0UserGroups(name string) ([]string, error) {
	res := []string{}

	if _, ok := rm.nameToIDMap[name]; !ok {
		return nil, errors.New("ID not found for the user")
	}

	groups, err := rm.authzClient.Authz.Users.GetAllGroups(rm.nameToIDMap[name])
	if err != nil {
		return nil, err
	}

	for _,  group := range groups {
		res = append(res, group.Name)
	}
	return res, nil
}

func (rm *RoleManager) getAuth0GroupUsers(name string) ([]string, error) {
	res := []string{}

	if _, ok := rm.nameToIDMap[name]; !ok {
		return nil, errors.New("ID not found for the role")
	}

	members, err := rm.authzClient.Authz.Groups.GetMembers(rm.nameToIDMap[name])
	if err != nil {
		return nil, err
	}

	for _,  user := range members.Users {
		res = append(res, user.Email)
	}
	return res, nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	return errors.New("not implemented")
}

// HasLink determines whether role: name1 inherits role: name2.
// domain is not used.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if len(domain) >= 1 {
		return false, errors.New("error: domain should not be used")
	}

	roles, err := rm.GetRoles(name1)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
	}
	return false, nil
}

// GetRoles gets the roles that a subject inherits.
// domain is not used.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	return rm.getAuth0UserGroups(name)
}

// GetUsers gets the users that inherits a subject.
// domain is not used.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	return rm.getAuth0GroupUsers(name)
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	return errors.New("not implemented")
}
