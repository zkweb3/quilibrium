package protobufs

const (
	TypeUrlPrefix                = "types.quilibrium.com"
	NamespacePrefix              = TypeUrlPrefix + "/quilibrium.node."
	AppPrefix                    = NamespacePrefix + "application.pb."
	ChannelPrefix                = NamespacePrefix + "channel.pb."
	ClockPrefix                  = NamespacePrefix + "clock.pb."
	KeysPrefix                   = NamespacePrefix + "keys.pb."
	DataPrefix                   = NamespacePrefix + "data.pb."
	NodePrefix                   = NamespacePrefix + "node.pb."
	AnnounceProverRequestType    = NodePrefix + "AnnounceProverRequest"
	TokenRequestsType            = NodePrefix + "TokenRequests"
	TokenRequestType             = NodePrefix + "TokenRequest"
	DataPeerListAnnounceType     = DataPrefix + "DataPeerListAnnounce"
	CeremonyPeerType             = DataPrefix + "DataPeer"
	AnnounceProverJoinType       = DataPrefix + "AnnounceProverJoin"
	AnnounceProverLeaveType      = DataPrefix + "AnnounceProverLeave"
	AnnounceProverPauseType      = DataPrefix + "AnnounceProverPause"
	AnnounceProverResumeType     = DataPrefix + "AnnounceProverResume"
	CeremonyCompressedSyncType   = DataPrefix + "DataCompressedSync"
	InclusionProofsMapType       = DataPrefix + "InclusionProofsMap"
	InclusionSegmentsMapType     = DataPrefix + "InclusionSegmentsMap"
	InclusionCommitmentsMapType  = DataPrefix + "InclusionCommitmentsMap"
	ApplicationType              = AppPrefix + "Application"
	ExecutionContextType         = AppPrefix + "ExecutionContext"
	MessageType                  = AppPrefix + "Message"
	IntrinsicExecutionOutputType = AppPrefix + "IntrinsicExecutionOutput"
	P2PChannelEnvelopeType       = ChannelPrefix + "P2PChannelEnvelope"
	MessageCiphertextType        = ChannelPrefix + "MessageCiphertext"
	ProvingKeyAnnouncementType   = ChannelPrefix + "ProvingKeyAnnouncement"
	ProvingKeyRequestType        = ChannelPrefix + "ProvingKeyRequest"
	InclusionAggregateProofType  = ChannelPrefix + "InclusionAggregateProof"
	InclusionCommitmentType      = ChannelPrefix + "InclusionCommitment"
	KeyBundleAnnouncementType    = ChannelPrefix + "KeyBundleAnnouncement"
	IdentityKeyType              = ChannelPrefix + "IdentityKey"
	SignedPreKeyType             = ChannelPrefix + "SignedPreKey"
	ClockFrameType               = ClockPrefix + "ClockFrame"
	ClockFramesRequestType       = ClockPrefix + "ClockFramesRequest"
	ClockFramesResponseType      = ClockPrefix + "ClockFramesResponse"
	Ed448PublicKeyType           = KeysPrefix + "Ed448PublicKey"
	Ed448PrivateKeyType          = KeysPrefix + "Ed448PrivateKey"
	Ed448SignatureType           = KeysPrefix + "Ed448Signature"
	X448PublicKeyType            = KeysPrefix + "X448PublicKey"
	X448PrivateKeyType           = KeysPrefix + "X448PrivateKey"
	PCASPublicKeyType            = KeysPrefix + "PCASPublicKey"
	PCASPrivateKeyType           = KeysPrefix + "PCASPrivateKey"
	BLS48581G1PublicKeyType      = KeysPrefix + "BLS48581G1PublicKey"
	BLS48581G1PrivateKeyType     = KeysPrefix + "BLS48581G1PrivateKey"
	BLS48581G2PublicKeyType      = KeysPrefix + "BLS48581G2PublicKey"
	BLS48581G2PrivateKeyType     = KeysPrefix + "BLS48581G2PrivateKey"
	SelfTestReportType           = NodePrefix + "SelfTestReport"
)
