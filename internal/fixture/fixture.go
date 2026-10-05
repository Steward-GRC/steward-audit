// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package fixture holds the sample data every test in this repo uses, from the
// Steward design brief. Nothing here is a real person, group or document.
package fixture

// People.
const (
	Alice = "alice" // site admin
	Bob   = "bob"   // author
	Carol = "carol" // approver
	Erin  = "erin"  // reader
	Grace = "grace" // compliance admin
	Heidi = "heidi" // group manager
)

// Groups.
const (
	FacilitiesTeam = "facilities-team"
	FinanceTeam    = "finance-team"
)

// Subjects.
const (
	DeskBookingPolicy   = "policy:POL-FACILITIES-000001"
	ExpenseClaimsPolicy = "policy:POL-EXPENSES-000002"
	TravelProcedure     = "policy:PRC-TRAVEL-000003"
	UserErin            = "user:erin"
	UserBob             = "user:bob"
)

// Actions.
const (
	PolicyPublished = "policy.published"
	PolicyViewed    = "policy.viewed"
)

// ErinKeyAlias is the personal-data key alias for Erin.
const ErinKeyAlias = "subject-key-erin"

// DocAddress is an address from the documentation range.
const DocAddress = "192.0.2.10"

// TSAURL is a time-stamp authority address that never resolves.
const TSAURL = "http://tsa.example.org"
