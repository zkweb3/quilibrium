//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package common

import (
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

// SignatureBlinding is a value used for computing blind signatures
type SignatureBlinding = curves.PairingScalar
