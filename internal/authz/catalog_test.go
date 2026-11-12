// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Bugs5382/go-authz/rbac"

	"github.com/Steward-GRC/steward-audit/internal/authz"
)

// The embedded catalog must be the canonical Steward catalog, byte for byte in
// meaning: rbac.Diff reports every difference between the two.
func TestEmbeddedCatalogMatchesCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/catalog.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := rbac.Parse(raw)
	if err != nil {
		t.Fatalf("canonical catalog does not parse: %v", err)
	}
	if diff := rbac.Diff(authz.Catalog, canonical); len(diff) != 0 {
		t.Fatalf("embedded catalog drifted from the canonical one (run task catalog:refresh COMMIT=<sha>):\n%s", strings.Join(diff, "\n"))
	}
}

func TestCatalogSourceIsRecorded(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/CATALOG_SOURCE")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"commit: ", "path: ", "repo: "} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("CATALOG_SOURCE lacks %q", key)
		}
	}
}

func TestEmbeddedCatalogIsByteIdenticalToCanonical(t *testing.T) {
	a, err := os.ReadFile("catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../testdata/catalog.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("internal/authz/catalog.json and testdata/catalog.canonical.json differ")
	}
}

// Role capability table: which roles hold audit.read and compliance.manage.
func TestRoleCapabilityTable(t *testing.T) {
	cases := []struct {
		role       authz.Role
		auditRead  bool
		manageComp bool
	}{
		{authz.RoleReader, false, false},
		{authz.RoleAuthor, false, false},
		{authz.RoleApprover, false, false},
		{authz.RoleTemplateAdmin, false, false},
		{authz.RoleComplianceAdmin, true, true},
		{authz.RoleSiteAdmin, true, true},
	}
	for _, c := range cases {
		t.Run(string(c.role), func(t *testing.T) {
			s := authz.Subject{Roles: []authz.Role{c.role}}
			if got := authz.HasCapability(s, authz.AuditRead); got != c.auditRead {
				t.Errorf("audit.read = %v, want %v", got, c.auditRead)
			}
			if got := authz.HasCapability(s, authz.ComplianceManage); got != c.manageComp {
				t.Errorf("compliance.manage = %v, want %v", got, c.manageComp)
			}
		})
	}
	if authz.HasCapability(authz.Subject{UserID: "u"}, authz.AuditRead) {
		t.Error("a subject with no roles must not hold audit.read")
	}
}

func TestParseRole(t *testing.T) {
	if r, err := authz.ParseRole("compliance-admin"); err != nil || r != authz.RoleComplianceAdmin {
		t.Fatalf("ParseRole(compliance-admin) = %q, %v", r, err)
	}
	if _, err := authz.ParseRole("admin"); err == nil {
		t.Fatal("an unknown role must not parse")
	}
}

// Every constant must exist in the catalog and every catalog name must have one.
func TestConstantsMatchTheCatalog(t *testing.T) {
	perms := []authz.Permission{authz.AuditRead, authz.ComplianceManage}
	for _, p := range perms {
		if _, err := authz.Catalog.ParsePermission(string(p)); err != nil {
			t.Errorf("constant %q is not in the catalog: %v", p, err)
		}
	}
	roles := []authz.Role{
		authz.RoleReader, authz.RoleAuthor, authz.RoleApprover,
		authz.RoleTemplateAdmin, authz.RoleComplianceAdmin, authz.RoleSiteAdmin,
	}
	for _, r := range roles {
		if _, err := authz.Catalog.ParseRole(string(r)); err != nil {
			t.Errorf("constant %q is not in the catalog: %v", r, err)
		}
	}
	for _, r := range authz.Catalog.RoleNames() {
		if !slices.Contains(roles, r) {
			t.Errorf("catalog role %q has no constant", r)
		}
	}
}
