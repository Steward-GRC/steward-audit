// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package authz is the audit service's view of the Steward permission catalog.
// The catalog (catalog.json) is the canonical Steward catalog, embedded here as
// a byte-identical copy; the mechanism is go-authz's rbac package. The types are
// aliases of rbac's so a Subject built here goes straight to rbac. Audit has no
// category rules, so only the capability check is exposed.
package authz

import (
	_ "embed"

	"github.com/Bugs5382/go-authz/rbac"
)

//go:embed catalog.json
var catalogJSON []byte

// Catalog is the parsed canonical catalog. It is read-only; a catalog that does
// not parse stops the process at start-up.
var Catalog = rbac.MustParse(catalogJSON)

type (
	Subject    = rbac.Subject
	Permission = rbac.Permission
	Role       = rbac.Role
)

// The permissions the audit service checks.
const (
	AuditRead        Permission = "audit.read"
	ComplianceManage Permission = "compliance.manage"
)

// The roles of catalog.json.
const (
	RoleReader          Role = "reader"
	RoleAuthor          Role = "author"
	RoleApprover        Role = "approver"
	RoleTemplateAdmin   Role = "template-admin"
	RoleComplianceAdmin Role = "compliance-admin"
	RoleSiteAdmin       Role = "site-admin"
)

// HasCapability reports whether s could hold p in at least one scope.
func HasCapability(s Subject, p Permission) bool {
	return Catalog.HasCapability(s, p)
}

// ParseRole returns the catalog role named s, or an error when it is not one.
func ParseRole(s string) (Role, error) { return Catalog.ParseRole(s) }
