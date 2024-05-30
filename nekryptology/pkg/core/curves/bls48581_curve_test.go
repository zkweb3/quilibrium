//
// Copyright Quilibrium, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
)

func TestScalarBls48581G1Zero(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Scalar.Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarBls48581G1One(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Scalar.One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarBls48581G1New(t *testing.T) {
	bls48581G1 := BLS48581G1()
	three := bls48581G1.Scalar.New(3)
	require.True(t, three.IsOdd())
	four := bls48581G1.Scalar.New(4)
	require.True(t, four.IsEven())
	neg1 := bls48581G1.Scalar.New(-1)
	require.True(t, neg1.IsEven())
	neg2 := bls48581G1.Scalar.New(-2)
	require.True(t, neg2.IsOdd())
}

func TestScalarBls48581G1Square(t *testing.T) {
	bls48581G1 := BLS48581G1()
	three := bls48581G1.Scalar.New(3)
	nine := bls48581G1.Scalar.New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarBls48581G1Cube(t *testing.T) {
	bls48581G1 := BLS48581G1()
	three := bls48581G1.Scalar.New(3)
	twentySeven := bls48581G1.Scalar.New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarBls48581G1Double(t *testing.T) {
	bls48581G1 := BLS48581G1()
	three := bls48581G1.Scalar.New(3)
	six := bls48581G1.Scalar.New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarBls48581G1Neg(t *testing.T) {
	bls48581G1 := BLS48581G1()
	one := bls48581G1.Scalar.One()
	neg1 := bls48581G1.Scalar.New(-1)
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := bls48581G1.Scalar.New(333333)
	expected := bls48581G1.Scalar.New(-333333)
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarBls48581G1Invert(t *testing.T) {
	bls48581G1 := BLS48581G1()
	nine := bls48581G1.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarBls48581)
	expected, err := bls48581G1.Scalar.SetBigInt(bhex("000000000000000007e51ad0414ec8f8799b3f49cc04d5850f9a0c8cf190b82a38f1b4c29e8b47c188b93dea0bb9f3ce3dec8654a0132439b9f49c13e8170ebbeae908716e2da522ab"))
	require.NoError(t, err)
	require.Equal(t, sa.Value.ToString(), expected.(*ScalarBls48581).Value.ToString())
}

func TestScalarBls48581G1Add(t *testing.T) {
	bls48581G1 := BLS48581G1()
	nine := bls48581G1.Scalar.New(9)
	six := bls48581G1.Scalar.New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := bls48581G1.Scalar.New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)
	qq := bls48581.NewBIGints(bls48581.CURVE_Order, nil)
	qq.Sub(bls48581.NewBIGint(3, nil))

	upper := &ScalarBls48581{
		Value: bls48581.NewBIGcopy(qq, nil),
	}
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarBls48581G1Sub(t *testing.T) {
	bls48581G1 := BLS48581G1()
	nine := bls48581G1.Scalar.New(9)
	six := bls48581G1.Scalar.New(6)
	n := bls48581.NewFPbig(bls48581.NewBIGints(bls48581.CURVE_Order, nil), nil)
	n.Sub(bls48581.NewFPint(3, nil), nil)

	expected := bls48581G1.Scalar.New(0).Sub(bls48581G1.Scalar.New(3))
	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(bls48581G1.Scalar.New(3)), 0)
}

func TestScalarBls48581G1Mul(t *testing.T) {
	bls48581G1 := BLS48581G1()
	nine := bls48581G1.Scalar.New(9)
	six := bls48581G1.Scalar.New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(bls48581G1.Scalar.New(54)), 0)
}

func TestScalarBls48581G1Div(t *testing.T) {
	bls48581G1 := BLS48581G1()
	nine := bls48581G1.Scalar.New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(bls48581G1.Scalar.New(1)), 0)
	require.Equal(t, bls48581G1.Scalar.New(54).Div(nine).Cmp(bls48581G1.Scalar.New(6)), 0)
}

func TestScalarBls48581G1Serialize(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Scalar.New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 73)
	require.Equal(t, sequence, []byte{0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff})
	ret, err := bls48581G1.Scalar.SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = bls48581G1.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 73)
		ret, err = bls48581G1.Scalar.SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarBls48581G1Nil(t *testing.T) {
	bls48581G1 := BLS48581G1()
	one := bls48581G1.Scalar.New(1)
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, one.Div(nil))
	require.Nil(t, bls48581G1.Scalar.Random(nil))
	require.Equal(t, one.Cmp(nil), -2)
	_, err := bls48581G1.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestScalarBls48581Point(t *testing.T) {
	bls48581G1 := BLS48581G1()
	_, ok := bls48581G1.Scalar.Point().(*PointBls48581G1)
	require.True(t, ok)
	bls48581G2 := BLS48581G2()
	_, ok = bls48581G2.Scalar.Point().(*PointBls48581G2)
	require.True(t, ok)
}

func TestPointBls48581G2Random(t *testing.T) {
	bls48581G2 := BLS48581G2()
	sc := bls48581G2.Point.Random(testRng())
	s, ok := sc.(*PointBls48581G2)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("12395013347e53a9b5f08f23f59170acb70d62611a1934a466d0bb0d8438014cdf89fb013d53845e9dedca76153f85c942d08cf5a996b8d0946841d3dca4ccabe703c89cb6cfc0beb20f4219db2c1b1b3da61bbc9718a7b9cb25b95a46e707e0ece266d55ecd493ae1edf036e08092e0792c1bce022aa95a84a702983a676430869ba4de1b1d85b263328824c771821728e807a2ab8956d05bf1c9063d4204a2f07aed76ecd8fba63ad00dd96f0b160f5cc655c5791bd61e25950b040840a23183994eee85a6d16a4fba7952ce4e40e0bc869d9a311db10ef758c51151035a1789e64f3efdffef40a6de05026a6e0937d536b4f57f3e26751747ed5fabdccf34e4ad6e8c00c9b94d4ea55b2b6f0c3b8b40acd0c134b446a54374bc13afd35613808adf700445e83602a52870bde1afefb5cb0a319ce6dd20df40784902156215977ea4fc5ba0d63b7edd75ed242c7e5e5157c4df6f7f685e42947d592da42be9e87d962f897144b41723d921f5108a06e4a83c457ee5b1f425cffb0d67b63e52bf3dc79e03fca3d2af0cc1e2d74c4fd77484d8c8d7887b951ec6c40327aebf0d1bfbfd80c1341d558ca95a3dad0f9a7527040d3c16d40a392e783f0ee91feeccab7ddaa1f45207f04f296a391504ff255e09cfc5d9365a5a08748ab5737647b9ca9e2821360434f0bf639b23a1950f02d0c68d748747a7a1bc54a1abaf154806a5b0ac00eed3b419316b19d32f2d6ddda6422db599f8fc095a8e7a9486ccc9fcc1750ef3ce47a1fc659101d7a5e21bf24372dcd50d08d9cd856068c0d32c7177371119f8ac3c11ed", 16)
	expectedY, _ := new(big.Int).SetString("a9c5ca5bb00686dbf0b9565e59b24b8d49efa7cf05efffb4310cb03d47e3cc26fd02c1ca593223c5820b807879775cf9dcc34c5a8071240d557cb0ee19a3f188af1a1bbe7f590e64a04be8c55982091812d8094b1b38add693685d53531b101e6e71fb2e2bd425b2da861f532173a6652ab0c18a22c76cd7752c9c2f97aa2b9676c739e3361cdb846694752212d91a65bbb031f35ac129720f85295716029b9481c04fa8b956c72626542e06ba88e3315d593b7f93e7ab15036c1830f2d80c98f265f0751606e8d297b61cfa245fcc81c8e437a3773704e3d7f110d36fe92586f8c5977dedcc6fe1b9966bbb58cc899397728c19316dee189b41403a4f8cc0882a21a12ccba2b6d4246a73496df2183f4c10ccf12beb44ebfd34a9fe36dfe42e6aaaa2d125b2ffd156006f0054589c9dca4b58542d0a4ccbb89f9a2c4b4f1fab0fe2c6caf2ecacb6b2f479797ff2db2025c3a7d497e860b316728ff555fd35729265c26b0bd5b0a7b5859886b00a05e4036ca09d53a7bf0a86015b21831e8c52031e40e65256c6d57c9d2adc2f6a021122e50b1664ee309675786495dcf72b56e86c5fdf9b33a7625a730d5f069107ce2479d20b64911f8d9513fd63e0a6fbfa6fd77a92e8269ee847ff98af8c711e4d7d96a4d9865bdc51d681e6cdece93d99b4769182e6406e798a3ad9d7c889b410287173c1fbd5bee448f8a5812a1c110eae05b35ef86eecae5383488483b3aec19dbad3644189da2a2300b34a49eb549d62643f9d06e222b77853f9af3365f2542d6e42f45cd3049a50dc77456ef50076fd947ddbbb1e043", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls48581G2.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls48581G2)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointBls48581G2Hash(t *testing.T) {
	var b [32]byte
	bls48581G2 := BLS48581G2()
	sc := bls48581G2.Point.Hash(b[:])
	s, ok := sc.(*PointBls48581G2)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("106b9bebe9a7d9b7342b468ec01b01bea3c30b49874b2352819b1cbcc5ba73b0f69b3b2c881138146fbf297e8f908729c9d2af4d5bd370535c5e11bee0cab9f117c51be1f73fed768b074209e2eace4f3a04559d3d576162506c119148c8192db93b33f1a2212193a7970d40a47e830ec44f4f969f2bd398df7a4c7113fd5e7f3d469697e4d0fd23b0940a04ea31555f3294040f02f4513f33aaa23c8b86bd734f0884ad34566202210e3e2d5a24bb2ce5de1cb62afbf5161f2f02effa6f58653f8046f7a115db221e58d5a5c01f5f773f71931b7ea807d1e49b570abdec252ca313582d09e627d5ea9f9ebc6bb03e258b6531e9a285cd9ada0c3aa0118cf5ac39e51690b29d089f816bc59f3daa950eee198a4b302e686e7ae87991b24567d46f1ade9606d8331f01213809d9fc4454a2e14b8c0f4d6cb32d57776390751b93620fb8e68f1eb686ddda3e3df0f6cac6dc25c308176fb115bd18ed3a48e1db45750a5e1cc7a116635f1680d0f006d63ff7042d0a1958e2149aa1b0916391d93fca6c5772ee4b3f4ca3eeaa92db9397a7371d7a3f8e53f81f67a0bee739f4e89235e087731cc0b51bada2381fc68be648526196e2cf9e093b2a6a474718d39159314610437e3049b04285d09cf56e20630a84000ee0c6b69d904ccd2d7b5e777a9ffe91f0dda0955879623e94d4d9d70cdc1b2214d196a10e21c05af3177d390a81006944b89bf992c230655a31cfddd404582ae7b7caf9e23d6e89c0c961a13a17f5423d3beb1aa7cfad6ad21ea9595748a38ee2a63f8e8c6f579887c0f9adb5e0f5de03afffd523", 16)
	expectedY, _ := new(big.Int).SetString("f4b6e12f594a7a5c5ae413126dc02e987fb2816ed5cb95b934c8282162a3ff4eeec088bff492a3a57d67e4df680f52900683378447627e5f9c7520033f11e02c958f754219f4f2a76023d6d7ce2998805823a8600045f672b45b62fbcd07e92df7ceecc1a03480d490e0c2d539b0379f08b26467366efc184a409d85742ef024e8627eef8b844bec5fec9e1d92f651d885102f067786a14a5cea3902387ccff802e23b04f0d09370671f903447fd1b9795ff32ed5931e7f85bc1634f80d94a208d620423b7292597c5d7b8e6180aaecba85950f17db311b3d05780a4ad89b8e4dc97419d57746145a156e49b94dc6c92fd74c91009fd276abaacb252da41d74d2e023ac35b3b640c067df40539739210ff1fda7f781b831c4a950d9f8b479c3f2bee328074f5a74802bc158fb235e7f448abf46be693a20fc5c95d02eb750817f866ef31f512e2650cf1315f766f2d746218291ec0c1c63cb083cd694ee767e656597e5709065e981ce9d7ea80746ea1852d849aef31d1ed0f287f03bc389c6a6e4e8994f69078256a2c2b6ffe35f84b6f201b9e85f49e553781e1c73fe5da3d8834edf250de5bc0f22ca17bf49f56d86a5b03873d90db5611c8d392f3fbc4464a424ad53baa123bd8a03b58645aecb4db985e1cf47c186343b5817808711efd1b638e95ed3eb6584bfaa47170ea3ebcb3905fe326e0b4bb63fdad369b7501111e82467a48319c18e5e177c13dbec61f79a2914a7d2ab92cbf535942325c87928b01d157e1a02bc43f4349e64f637fdc7811eb2fbd1526b03b4baa280118a37ac19470f0855a8e6", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
}

func TestPointBls48581G2Generator(t *testing.T) {
	bls48581G2 := BLS48581G2()
	sc := bls48581G2.Point.Generator()
	s, ok := sc.(*PointBls48581G2)
	require.True(t, ok)
	require.Equal(t, true, s.Value.Equals(bls48581.ECP8_generator()))
}

func TestPointBls48581G2Double(t *testing.T) {
	bls48581G2 := BLS48581G2()
	g := bls48581G2.Point.Generator()
	gg2 := g.Double()
	require.True(t, gg2.Equal(g.Mul(bls48581G2.Scalar.New(2))))
	i := bls48581G2.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls48581G2Neg(t *testing.T) {
	bls48581G2 := BLS48581G1()
	g := bls48581G2.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(bls48581G2.Point.Generator()))
	require.True(t, bls48581G2.Point.Identity().Neg().Equal(bls48581G2.Point.Identity()))
}

func TestPointBls48581G2Add(t *testing.T) {
	bls48581G2 := BLS48581G2()
	pt := bls48581G2.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(bls48581G2.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls48581G2Sub(t *testing.T) {
	bls48581G2 := BLS48581G2()
	g := bls48581G2.Point.Generator()
	pt := bls48581G2.Point.Generator().Mul(bls48581G2.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls48581G2Mul(t *testing.T) {
	bls48581G2 := BLS48581G2()
	g := bls48581G2.Point.Generator()
	pt := bls48581G2.Point.Generator().Mul(bls48581G2.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls48581G2Serialize(t *testing.T) {
	bls48581G2 := BLS48581G2()
	ss := bls48581G2.Scalar.Random(testRng())
	g := bls48581G2.Point.Generator()

	ppt := g.Mul(ss)
	require.Equal(t, ppt.ToAffineCompressed(), []byte{0x2, 0x4, 0xb2, 0xe, 0xcb, 0xd0, 0x67, 0x25, 0xf7, 0x3b, 0x30, 0x9a, 0x28, 0x7f, 0x2f, 0x46, 0xf0, 0xd, 0x1b, 0x86, 0xc2, 0x32, 0x44, 0xbf, 0xc4, 0x3d, 0xcc, 0xa1, 0x72, 0xd2, 0x7d, 0x63, 0x71, 0x6e, 0x2f, 0x78, 0x3b, 0x1d, 0x45, 0xa, 0xa2, 0x9b, 0x56, 0x81, 0xdb, 0xa0, 0xdb, 0x7b, 0x76, 0xb0, 0x90, 0x3b, 0xd4, 0x14, 0x4, 0xb, 0x97, 0x1b, 0x19, 0x18, 0x54, 0xc1, 0x4e, 0x8b, 0x14, 0x21, 0xfc, 0xbe, 0x17, 0xe, 0xc9, 0x73, 0x1a, 0x12, 0x6, 0xe4, 0x45, 0xd, 0x8f, 0x95, 0x5f, 0xde, 0x23, 0x29, 0x18, 0x67, 0xaf, 0x4e, 0x36, 0xd7, 0x7, 0xaa, 0x2b, 0xbb, 0x8f, 0x7c, 0xe8, 0x2d, 0x84, 0x67, 0xd7, 0x82, 0xea, 0xe7, 0xb9, 0x16, 0x9a, 0x16, 0x5b, 0xf5, 0x15, 0x1, 0x65, 0x63, 0xe9, 0xb3, 0x53, 0x35, 0x57, 0xdc, 0x9, 0x59, 0xe0, 0x32, 0x6e, 0xfd, 0x1d, 0x29, 0xd7, 0x4e, 0x85, 0x7e, 0x15, 0x6f, 0x10, 0xbf, 0x54, 0x6e, 0x64, 0x57, 0x9, 0xa1, 0x62, 0x17, 0x41, 0xe8, 0x7, 0x6, 0x7b, 0xbe, 0x4e, 0xba, 0xad, 0x2c, 0xdc, 0x2f, 0xc0, 0x5e, 0x59, 0xde, 0x33, 0x9b, 0x38, 0x47, 0x7d, 0x9e, 0xad, 0x93, 0xec, 0xd2, 0x76, 0xfe, 0xc1, 0xd2, 0xae, 0x37, 0x34, 0xbf, 0xc, 0x89, 0x73, 0x9f, 0xcc, 0x9c, 0xb4, 0xc7, 0x90, 0xda, 0x2d, 0x3, 0x1c, 0xad, 0xf3, 0xfa, 0x48, 0x97, 0x3a, 0xb9, 0x23, 0xc3, 0x4f, 0xe, 0x13, 0xc, 0xe2, 0x17, 0xbe, 0x7c, 0xeb, 0xdc, 0x63, 0x63, 0x69, 0xc5, 0xa8, 0x26, 0x7d, 0xa8, 0x65, 0xa, 0x8, 0x1a, 0x76, 0xdc, 0xe4, 0xe5, 0xd6, 0xa1, 0x22, 0xfa, 0xcb, 0x26, 0xf9, 0xc5, 0x7f, 0x31, 0x20, 0x6c, 0x4f, 0xcb, 0xac, 0x48, 0xb, 0xc9, 0x53, 0x24, 0x57, 0xfe, 0x71, 0xdf, 0x67, 0xcb, 0x36, 0xdd, 0x4d, 0x52, 0x52, 0x36, 0xf4, 0xd3, 0x8f, 0x9b, 0x7b, 0xf2, 0xaf, 0x28, 0xae, 0x4a, 0xf3, 0x7a, 0x6a, 0xbb, 0x4e, 0x63, 0x54, 0xdd, 0x9d, 0x6c, 0xe4, 0xb7, 0xb7, 0xe9, 0x76, 0x3e, 0xef, 0x93, 0x51, 0x79, 0xfb, 0xb7, 0xf4, 0x3c, 0x8c, 0x4, 0x61, 0x11, 0xe8, 0x19, 0xd1, 0xa6, 0x6c, 0x4, 0xd0, 0xae, 0x61, 0xd6, 0x80, 0xd7, 0xde, 0xac, 0x39, 0x76, 0x53, 0xe5, 0xf4, 0xd3, 0x2d, 0x7d, 0x8, 0x2f, 0xc1, 0x7, 0xdc, 0x58, 0xd8, 0x3c, 0xd3, 0xd, 0xf0, 0xe6, 0xcd, 0x29, 0xa0, 0xe6, 0xdb, 0x5f, 0xc3, 0x24, 0x99, 0xb9, 0xe0, 0x7, 0x58, 0x74, 0xc6, 0x3, 0xa0, 0x7, 0xa5, 0x7a, 0xb0, 0xee, 0x6d, 0x53, 0xf7, 0xd3, 0xce, 0x31, 0xf5, 0xe1, 0xd5, 0x72, 0xda, 0x70, 0x99, 0x5a, 0x0, 0xb9, 0xa1, 0x18, 0x41, 0x7a, 0x7a, 0xb0, 0xcc, 0xaa, 0xc, 0xbc, 0x82, 0x22, 0x70, 0xb, 0xd3, 0xb6, 0x11, 0xf, 0x1f, 0x46, 0xe, 0xcf, 0xab, 0x6c, 0x1f, 0xdb, 0x1b, 0xb4, 0xa5, 0xd6, 0x62, 0x4a, 0x11, 0xd, 0xa1, 0x2, 0x70, 0x19, 0x46, 0xa, 0x69, 0x0, 0xca, 0xb1, 0xa5, 0xed, 0x45, 0x28, 0xf4, 0xbd, 0x65, 0x4a, 0x59, 0xf4, 0x27, 0x50, 0x3e, 0xbd, 0xf7, 0x46, 0x67, 0x61, 0x99, 0xbd, 0x59, 0xf0, 0xa2, 0x85, 0x14, 0x36, 0x48, 0xd, 0x1a, 0xa8, 0x3d, 0x4b, 0x4a, 0xbb, 0xb0, 0x46, 0x62, 0x38, 0x29, 0x8a, 0x1c, 0x11, 0xf, 0xdc, 0x71, 0x26, 0x4b, 0x7c, 0xc8, 0x66, 0x1a, 0x6c, 0x29, 0x8b, 0x44, 0x4b, 0xb4, 0x11, 0x35, 0x6, 0x98, 0x30, 0xa2, 0x53, 0xed, 0xfa, 0x1c, 0x86, 0x42, 0xe2, 0xb3, 0x25, 0x2c, 0xba, 0xa, 0xac, 0xba, 0x4f, 0xaf, 0xe, 0x1e, 0x65, 0x6b, 0x3f, 0x4f, 0x28, 0x76, 0xcd, 0x25, 0x6a, 0x77, 0xe4, 0x2d, 0x44, 0x3b, 0x7d, 0xc, 0xf0, 0x9e, 0x2, 0x9, 0xb5, 0xf8, 0xdd, 0xea, 0xd4, 0x9, 0xfe, 0xf, 0x83, 0x63, 0x2, 0x8f, 0xd1, 0x12, 0x16, 0x81, 0xd9, 0xad, 0xdd, 0x3, 0x32, 0x97, 0x2c, 0x3e, 0xf5, 0x88, 0x1d, 0x2, 0x63, 0x9d, 0x33, 0xa, 0xc8, 0x8a, 0x7, 0x1d, 0x6f, 0x30, 0x40, 0xfa, 0x6e, 0x3, 0xba, 0x7c, 0xe, 0x0, 0x56, 0x56, 0xad, 0xfe, 0xee, 0x3e, 0x65, 0x87, 0x80, 0x52, 0x6c, 0xeb, 0x1f, 0x61, 0x74, 0xc, 0x10, 0xeb, 0x37, 0x1a, 0xbd, 0xab, 0x86, 0x60, 0xf2, 0xfd})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x4, 0x4, 0xb2, 0xe, 0xcb, 0xd0, 0x67, 0x25, 0xf7, 0x3b, 0x30, 0x9a, 0x28, 0x7f, 0x2f, 0x46, 0xf0, 0xd, 0x1b, 0x86, 0xc2, 0x32, 0x44, 0xbf, 0xc4, 0x3d, 0xcc, 0xa1, 0x72, 0xd2, 0x7d, 0x63, 0x71, 0x6e, 0x2f, 0x78, 0x3b, 0x1d, 0x45, 0xa, 0xa2, 0x9b, 0x56, 0x81, 0xdb, 0xa0, 0xdb, 0x7b, 0x76, 0xb0, 0x90, 0x3b, 0xd4, 0x14, 0x4, 0xb, 0x97, 0x1b, 0x19, 0x18, 0x54, 0xc1, 0x4e, 0x8b, 0x14, 0x21, 0xfc, 0xbe, 0x17, 0xe, 0xc9, 0x73, 0x1a, 0x12, 0x6, 0xe4, 0x45, 0xd, 0x8f, 0x95, 0x5f, 0xde, 0x23, 0x29, 0x18, 0x67, 0xaf, 0x4e, 0x36, 0xd7, 0x7, 0xaa, 0x2b, 0xbb, 0x8f, 0x7c, 0xe8, 0x2d, 0x84, 0x67, 0xd7, 0x82, 0xea, 0xe7, 0xb9, 0x16, 0x9a, 0x16, 0x5b, 0xf5, 0x15, 0x1, 0x65, 0x63, 0xe9, 0xb3, 0x53, 0x35, 0x57, 0xdc, 0x9, 0x59, 0xe0, 0x32, 0x6e, 0xfd, 0x1d, 0x29, 0xd7, 0x4e, 0x85, 0x7e, 0x15, 0x6f, 0x10, 0xbf, 0x54, 0x6e, 0x64, 0x57, 0x9, 0xa1, 0x62, 0x17, 0x41, 0xe8, 0x7, 0x6, 0x7b, 0xbe, 0x4e, 0xba, 0xad, 0x2c, 0xdc, 0x2f, 0xc0, 0x5e, 0x59, 0xde, 0x33, 0x9b, 0x38, 0x47, 0x7d, 0x9e, 0xad, 0x93, 0xec, 0xd2, 0x76, 0xfe, 0xc1, 0xd2, 0xae, 0x37, 0x34, 0xbf, 0xc, 0x89, 0x73, 0x9f, 0xcc, 0x9c, 0xb4, 0xc7, 0x90, 0xda, 0x2d, 0x3, 0x1c, 0xad, 0xf3, 0xfa, 0x48, 0x97, 0x3a, 0xb9, 0x23, 0xc3, 0x4f, 0xe, 0x13, 0xc, 0xe2, 0x17, 0xbe, 0x7c, 0xeb, 0xdc, 0x63, 0x63, 0x69, 0xc5, 0xa8, 0x26, 0x7d, 0xa8, 0x65, 0xa, 0x8, 0x1a, 0x76, 0xdc, 0xe4, 0xe5, 0xd6, 0xa1, 0x22, 0xfa, 0xcb, 0x26, 0xf9, 0xc5, 0x7f, 0x31, 0x20, 0x6c, 0x4f, 0xcb, 0xac, 0x48, 0xb, 0xc9, 0x53, 0x24, 0x57, 0xfe, 0x71, 0xdf, 0x67, 0xcb, 0x36, 0xdd, 0x4d, 0x52, 0x52, 0x36, 0xf4, 0xd3, 0x8f, 0x9b, 0x7b, 0xf2, 0xaf, 0x28, 0xae, 0x4a, 0xf3, 0x7a, 0x6a, 0xbb, 0x4e, 0x63, 0x54, 0xdd, 0x9d, 0x6c, 0xe4, 0xb7, 0xb7, 0xe9, 0x76, 0x3e, 0xef, 0x93, 0x51, 0x79, 0xfb, 0xb7, 0xf4, 0x3c, 0x8c, 0x4, 0x61, 0x11, 0xe8, 0x19, 0xd1, 0xa6, 0x6c, 0x4, 0xd0, 0xae, 0x61, 0xd6, 0x80, 0xd7, 0xde, 0xac, 0x39, 0x76, 0x53, 0xe5, 0xf4, 0xd3, 0x2d, 0x7d, 0x8, 0x2f, 0xc1, 0x7, 0xdc, 0x58, 0xd8, 0x3c, 0xd3, 0xd, 0xf0, 0xe6, 0xcd, 0x29, 0xa0, 0xe6, 0xdb, 0x5f, 0xc3, 0x24, 0x99, 0xb9, 0xe0, 0x7, 0x58, 0x74, 0xc6, 0x3, 0xa0, 0x7, 0xa5, 0x7a, 0xb0, 0xee, 0x6d, 0x53, 0xf7, 0xd3, 0xce, 0x31, 0xf5, 0xe1, 0xd5, 0x72, 0xda, 0x70, 0x99, 0x5a, 0x0, 0xb9, 0xa1, 0x18, 0x41, 0x7a, 0x7a, 0xb0, 0xcc, 0xaa, 0xc, 0xbc, 0x82, 0x22, 0x70, 0xb, 0xd3, 0xb6, 0x11, 0xf, 0x1f, 0x46, 0xe, 0xcf, 0xab, 0x6c, 0x1f, 0xdb, 0x1b, 0xb4, 0xa5, 0xd6, 0x62, 0x4a, 0x11, 0xd, 0xa1, 0x2, 0x70, 0x19, 0x46, 0xa, 0x69, 0x0, 0xca, 0xb1, 0xa5, 0xed, 0x45, 0x28, 0xf4, 0xbd, 0x65, 0x4a, 0x59, 0xf4, 0x27, 0x50, 0x3e, 0xbd, 0xf7, 0x46, 0x67, 0x61, 0x99, 0xbd, 0x59, 0xf0, 0xa2, 0x85, 0x14, 0x36, 0x48, 0xd, 0x1a, 0xa8, 0x3d, 0x4b, 0x4a, 0xbb, 0xb0, 0x46, 0x62, 0x38, 0x29, 0x8a, 0x1c, 0x11, 0xf, 0xdc, 0x71, 0x26, 0x4b, 0x7c, 0xc8, 0x66, 0x1a, 0x6c, 0x29, 0x8b, 0x44, 0x4b, 0xb4, 0x11, 0x35, 0x6, 0x98, 0x30, 0xa2, 0x53, 0xed, 0xfa, 0x1c, 0x86, 0x42, 0xe2, 0xb3, 0x25, 0x2c, 0xba, 0xa, 0xac, 0xba, 0x4f, 0xaf, 0xe, 0x1e, 0x65, 0x6b, 0x3f, 0x4f, 0x28, 0x76, 0xcd, 0x25, 0x6a, 0x77, 0xe4, 0x2d, 0x44, 0x3b, 0x7d, 0xc, 0xf0, 0x9e, 0x2, 0x9, 0xb5, 0xf8, 0xdd, 0xea, 0xd4, 0x9, 0xfe, 0xf, 0x83, 0x63, 0x2, 0x8f, 0xd1, 0x12, 0x16, 0x81, 0xd9, 0xad, 0xdd, 0x3, 0x32, 0x97, 0x2c, 0x3e, 0xf5, 0x88, 0x1d, 0x2, 0x63, 0x9d, 0x33, 0xa, 0xc8, 0x8a, 0x7, 0x1d, 0x6f, 0x30, 0x40, 0xfa, 0x6e, 0x3, 0xba, 0x7c, 0xe, 0x0, 0x56, 0x56, 0xad, 0xfe, 0xee, 0x3e, 0x65, 0x87, 0x80, 0x52, 0x6c, 0xeb, 0x1f, 0x61, 0x74, 0xc, 0x10, 0xeb, 0x37, 0x1a, 0xbd, 0xab, 0x86, 0x60, 0xf2, 0xfd, 0x6, 0x1d, 0x73, 0x30, 0xb7, 0xc8, 0x21, 0xdf, 0xc, 0xf9, 0x3f, 0x97, 0xa8, 0xa5, 0xfc, 0xa1, 0x76, 0xea, 0x0, 0x64, 0x96, 0x70, 0x4d, 0x28, 0xd4, 0xad, 0x23, 0x3a, 0x6, 0x1b, 0xc3, 0x9d, 0x89, 0xa0, 0xdc, 0x2f, 0xbe, 0xcd, 0x43, 0xe1, 0x67, 0xcc, 0x92, 0x8b, 0xf0, 0x55, 0x56, 0xc4, 0xde, 0x60, 0x48, 0xe9, 0x14, 0x4f, 0x27, 0xa8, 0xc, 0x7f, 0x8a, 0xdf, 0x35, 0x5d, 0x44, 0xae, 0x56, 0x3a, 0x44, 0xdd, 0x44, 0x4e, 0xff, 0xdf, 0xca, 0xa, 0xa4, 0x82, 0xc7, 0x77, 0x33, 0xe9, 0xf1, 0x39, 0xbe, 0x33, 0xe, 0x79, 0xbe, 0x80, 0x61, 0x10, 0xc, 0x90, 0xf6, 0x6c, 0x4d, 0x16, 0x49, 0x91, 0xfb, 0xfc, 0xe1, 0x4e, 0x77, 0x18, 0xf3, 0xf3, 0x34, 0x31, 0x88, 0xa7, 0x9f, 0x86, 0x3f, 0xec, 0xe4, 0xb9, 0x1b, 0x16, 0xa, 0xec, 0x72, 0x3c, 0x9d, 0x30, 0x57, 0x12, 0x4e, 0x7f, 0x3b, 0xbd, 0x2a, 0x6b, 0xad, 0x81, 0xed, 0x2f, 0x8a, 0x45, 0x9e, 0x91, 0xd, 0xf4, 0x9d, 0x1, 0xfb, 0x34, 0x7, 0xdf, 0x96, 0x15, 0xbc, 0x9e, 0x62, 0x70, 0xdb, 0x47, 0xef, 0x1e, 0xd0, 0xb8, 0x56, 0x91, 0xe8, 0x26, 0xe9, 0xcb, 0xae, 0x11, 0x4a, 0x93, 0xaa, 0x31, 0x84, 0xcf, 0x1e, 0xe3, 0x43, 0x90, 0x81, 0xc8, 0xbb, 0xfa, 0xa1, 0x5a, 0x35, 0xc1, 0xb9, 0x93, 0xb0, 0x52, 0x26, 0xb9, 0x5d, 0x29, 0x78, 0xde, 0x86, 0xa9, 0xcf, 0xcc, 0x77, 0x9, 0x1f, 0xf5, 0x3d, 0x82, 0x8d, 0x93, 0xf2, 0x39, 0xdc, 0x18, 0x47, 0x33, 0x6a, 0xb0, 0xbd, 0xa6, 0xfe, 0xa, 0xac, 0x24, 0xd0, 0x0, 0xcb, 0xb8, 0x30, 0x8f, 0xb9, 0x59, 0x90, 0x1a, 0x7c, 0xa6, 0xb0, 0xc9, 0x5e, 0x80, 0x4e, 0xc7, 0x73, 0x42, 0x48, 0x76, 0xea, 0xd6, 0x7b, 0x72, 0x6, 0xfd, 0xbc, 0xe5, 0xd4, 0x93, 0x2c, 0xfc, 0x26, 0x5, 0xac, 0xfb, 0xa1, 0xb, 0xf5, 0x4c, 0xc5, 0x9c, 0x1f, 0x3a, 0x97, 0xa9, 0xd, 0x3e, 0xf4, 0x8d, 0x42, 0x47, 0x1c, 0xe3, 0xf3, 0xfe, 0x54, 0xa7, 0x6, 0x20, 0xa1, 0x34, 0x43, 0x28, 0x9f, 0x11, 0xd9, 0x8c, 0x9, 0x73, 0xaf, 0x9a, 0x30, 0xea, 0x8d, 0xc, 0x34, 0xd9, 0x3a, 0x93, 0xd3, 0xed, 0xaf, 0x66, 0x5c, 0xaf, 0x3a, 0x4a, 0x5d, 0xc4, 0x30, 0x74, 0x57, 0x5f, 0x9d, 0x81, 0x11, 0x79, 0x7b, 0xb7, 0x8b, 0xa, 0x15, 0x1d, 0xc4, 0xce, 0xfa, 0x2c, 0xf0, 0xbe, 0xa9, 0x61, 0xc7, 0x6b, 0x1c, 0xaf, 0x8c, 0x40, 0xd6, 0x8a, 0xef, 0xa1, 0xad, 0x33, 0xf9, 0x97, 0xef, 0xb6, 0xb8, 0xc6, 0x4b, 0x29, 0xa9, 0xaf, 0x7f, 0xfc, 0xf8, 0x3, 0xe0, 0x1a, 0x51, 0x0, 0xd6, 0xdd, 0xcb, 0xb7, 0x57, 0xc7, 0xe7, 0x40, 0x3d, 0x4, 0xbf, 0x41, 0x91, 0x9b, 0xec, 0x1a, 0x44, 0xb7, 0x5b, 0xd9, 0x79, 0xfd, 0xf3, 0x8d, 0xb1, 0x39, 0xee, 0x9b, 0xce, 0x8, 0x13, 0x31, 0xa1, 0x9f, 0x87, 0x9f, 0x2b, 0xed, 0x45, 0xb3, 0x42, 0x8b, 0x4e, 0x3e, 0x40, 0x21, 0x83, 0xc4, 0x15, 0xce, 0x4f, 0xdb, 0xb4, 0x6d, 0x73, 0xc6, 0xdf, 0xc1, 0x97, 0x42, 0xe9, 0xc6, 0xba, 0x10, 0xb5, 0xfc, 0x53, 0x78, 0x2c, 0xaa, 0x80, 0xf8, 0x1, 0x74, 0xe4, 0x93, 0x3d, 0x26, 0xd2, 0x0, 0xa8, 0x6e, 0x9d, 0x33, 0x1e, 0x54, 0x40, 0x1, 0xdf, 0x6d, 0xb, 0xac, 0xf, 0x67, 0x31, 0xf7, 0xbc, 0xe5, 0xd3, 0xf9, 0x3c, 0xf6, 0xe3, 0x23, 0x1, 0xda, 0xb1, 0xb, 0xbd, 0xae, 0xa4, 0xb4, 0xc6, 0xf5, 0xee, 0xd9, 0xe6, 0x4d, 0x50, 0xab, 0xa0, 0xe, 0x99, 0x43, 0xfc, 0x34, 0x9f, 0x12, 0xd6, 0x4d, 0x70, 0x1, 0x22, 0x3c, 0xed, 0x64, 0x49, 0xb4, 0xbe, 0xd8, 0x25, 0xf7, 0x35, 0xb, 0x75, 0xd, 0x3c, 0x13, 0xf4, 0xb5, 0xc3, 0x54, 0xc8, 0x7a, 0xb3, 0x9b, 0x4b, 0x98, 0x3e, 0x6d, 0x5a, 0xe0, 0xd8, 0x98, 0x81, 0xa2, 0x72, 0xb3, 0xf8, 0x26, 0x75, 0xe0, 0x37, 0xa5, 0x30, 0xb9, 0x58, 0x27, 0x71, 0xbf, 0x71, 0x56, 0xfe, 0xbe, 0x5b, 0x11, 0x5e, 0xbe, 0xd4, 0x7b, 0x3d, 0xe3, 0xe0, 0x30, 0xbb, 0xa9, 0xe1, 0xcc, 0x63, 0x8d, 0x78, 0xa2, 0xe4, 0x73, 0xdc, 0x58, 0x98, 0x1b, 0x43, 0x1a, 0xa8, 0x10, 0x2, 0xb7, 0x1e, 0xec, 0x84, 0xa8})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls48581G2.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 585)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 1169)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls48581G2Nil(t *testing.T) {
	bls48581G2 := BLS48581G2()
	one := bls48581G2.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, bls48581G2.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := bls48581G2.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointBls48581G1Random(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Point.Random(testRng())
	s, ok := sc.(*PointBls48581G1)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("044e04484c6f85044de7ea5a4f56f86028d6689be3f3156b67a5f1bb84ce7958c6083bbbff724481d7c5d8b018876c4bfac2775bc94a7f1dadca0356cb1951b2d1ed472829e323f9a9", 16)
	expectedY, _ := new(big.Int).SetString("04a1762fc005980e26e53b06a2cf2717a866e9aa5e2e9a486da1e1c9da7583897f605aed3b0bb99c2654d8fdfab67b3ecc2caa9f8f495580def65886fbe162d7e2404237bc1ac57733", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls48581G1.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls48581G1)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointBls48581G1Hash(t *testing.T) {
	var b [32]byte
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Point.Hash(b[:])
	s, ok := sc.(*PointBls48581G1)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("09b0bb0ec869bf35ca3efcc974413c6e273a9855f79cf9ddc2b1a362e6b3c822aaf3ed7a08155c11e53094f270743ebeb9c45d09ef6417bd743cec4f4293634bfe344ec87efc306260", 16)
	expectedY, _ := new(big.Int).SetString("12776c7e26039acc00844149b4405980b2ace42810526da41c8de4f7b2c7de98f5f70fe76ca4dd25d90fac8683e68e4c0f7f071eff23fda25f4023ad5d63b9add3387b581375ed2e92", 16)
	require.Equal(t, s.X(), expectedX)
	require.Equal(t, s.Y(), expectedY)
}

func TestPointBls48581G1Identity(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
}

func TestPointBls48581G1Generator(t *testing.T) {
	bls48581G1 := BLS48581G1()
	sc := bls48581G1.Point.Generator()
	s, ok := sc.(*PointBls48581G1)
	require.True(t, ok)
	require.Equal(t, true, s.Value.Equals(bls48581.ECP_generator()))
}

func TestPointBls48581G1Set(t *testing.T) {
	bls48581G1 := BLS48581G1()
	iden, err := bls48581G1.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	generator := bls48581G1.Point.Generator().ToAffineUncompressed()
	_, err = bls48581G1.Point.Set(new(big.Int).SetBytes(generator[1:74]), new(big.Int).SetBytes(generator[74:]))
	require.NoError(t, err)
}

func TestPointBls48581G1Double(t *testing.T) {
	bls48581G1 := BLS48581G1()
	g := bls48581G1.Point.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(bls48581G1.Scalar.New(2))))
	i := bls48581G1.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointBls48581G1Neg(t *testing.T) {
	bls48581G1 := BLS48581G1()
	g := bls48581G1.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(bls48581G1.Point.Generator()))
	require.True(t, bls48581G1.Point.Identity().Neg().Equal(bls48581G1.Point.Identity()))
}

func TestPointBls48581G1Add(t *testing.T) {
	bls48581G1 := BLS48581G1()
	pt := bls48581G1.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(bls48581G1.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls48581G1Sub(t *testing.T) {
	bls48581G1 := BLS48581G1()
	g := bls48581G1.Point.Generator()
	pt := bls48581G1.Point.Generator().Mul(bls48581G1.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls48581G1Mul(t *testing.T) {
	bls48581G1 := BLS48581G1()
	g := bls48581G1.Point.Generator()
	pt := bls48581G1.Point.Generator().Mul(bls48581G1.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls48581G1Serialize(t *testing.T) {
	bls48581G1 := BLS48581G1()
	g := bls48581G1.Point.Generator()

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls48581G1.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 74)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 147)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointBls48581G1Nil(t *testing.T) {
	bls48581G1 := BLS48581G1()
	one := bls48581G1.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, bls48581G1.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := bls48581G1.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointBls48581G1SumOfProducts(t *testing.T) {
	lhs := new(PointBls48581G1).Generator().Mul(new(ScalarBls48581).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointBls48581G1).Generator()
	}
	scalars := []Scalar{
		new(ScalarBls48581).New(8),
		new(ScalarBls48581).New(9),
		new(ScalarBls48581).New(10),
		new(ScalarBls48581).New(11),
		new(ScalarBls48581).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}
