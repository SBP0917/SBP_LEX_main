--------------------------- MODULE SBPLexAuthority ---------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************
 * Bounded safety model for the minimal SBP-LEX authority/effect protocol.
 *
 * This model deliberately treats signatures, hashes, durable atomicity and
 * independent re-verification as ideal predicates.  It is a design-level
 * protocol model, not an implementation or production assurance claim.
*)

CONSTANTS
    Traversals,
    Requests,
    States,
    Effects,
    Adapters,
    ExtensionBindings,
    ExtensionConfigurations,
    SafeEffects,
    HighestConsequenceEffects,
    ProofTTL,
    PrepareTTL,
    LeaseTTL,
    WatchdogTTL,
    HSMTTL,
    InhibitTTL,
    MaxTime

ASSUME /\ Traversals # {}
       /\ Requests # {}
       /\ States # {}
       /\ Effects # {}
       /\ Adapters # {}
       /\ ExtensionBindings # {}
       /\ ExtensionConfigurations # {}
       /\ SafeEffects \subseteq Effects
       /\ HighestConsequenceEffects \subseteq Effects
       /\ ProofTTL \in Nat
       /\ PrepareTTL \in Nat
       /\ LeaseTTL \in Nat
       /\ WatchdogTTL \in Nat
       /\ HSMTTL \in Nat
       /\ InhibitTTL \in Nat
       /\ MaxTime \in Nat

Bindings ==
    [present : {TRUE},
     request : Requests,
     state   : States,
     effect  : Effects,
     adapter : Adapters,
     extensionAdmissionMode : {"EXTENSIONS_DISABLED"},
     extensionSchema : {"SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED"},
     extensionConfiguration : ExtensionConfigurations,
     extensionAdmissionBinding : ExtensionBindings]

(***************************************************************************
 * TLC requires values compared or fingerprinted together to have compatible
 * shapes.  The absent value is therefore a tagged record with the same fields
 * and field types as every real binding, never a string/record union.
*)
NoBinding ==
    [present |-> FALSE,
     request |-> CHOOSE request \in Requests : TRUE,
     state   |-> CHOOSE state \in States : TRUE,
     effect  |-> CHOOSE effect \in Effects : TRUE,
     adapter |-> CHOOSE adapter \in Adapters : TRUE,
     extensionAdmissionMode |-> "EXTENSIONS_DISABLED",
     extensionSchema |-> "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED",
     extensionConfiguration |-> CHOOSE config \in ExtensionConfigurations : TRUE,
     extensionAdmissionBinding |-> CHOOSE binding \in ExtensionBindings : TRUE]

MaybeBinding == Bindings \cup {NoBinding}

CustodyStatuses == {"UNASSESSED", "PRODUCTION"}
InhibitDecisions == {"NONE", "CLEAR"}
AuthorityOrigins == {"NONE", "SOLE_COMMIT"}

RejectKinds == {
    "DIVERGENT_CONVERGENCE",
    "PREPARE_WITHOUT_EXACT_PROOF",
    "PREPARE_REPLAY",
    "PROOF_EXPIRED",
    "PREPARE_EXPIRED",
    "MUTATED_BINDING",
    "COMMIT_WITHOUT_MATCHING_PREPARE",
    "COMMIT_REPLAY",
    "LEASE_BEFORE_COMMIT",
    "LEASE_EXPIRED",
    "ADAPTER_MISMATCH",
    "EFFECT_MISMATCH",
    "REDEMPTION_REPLAY",
    "SAFETY_ENVELOPE_BLOCK",
    "EFFECT_WITHOUT_LEASE_INTERLOCK",
    "RECEIPT_BINDING_MISMATCH",
    "RECEIPT_SIGNATURE_INVALID",
    "RECEIPT_DUPLICATE",
    "WATCHDOG_TIMEOUT",
    "FIXTURE_CUSTODY",
    "NONPRODUCTION_CUSTODY",
    "HSM_UNAVAILABLE",
    "HSM_STALE",
    "INHIBIT_BLOCK",
    "INHIBIT_STOP",
    "INHIBIT_UNAVAILABLE",
    "INHIBIT_STALE",
    "INHIBIT_BINDING_MISMATCH",
    "INHIBIT_NOT_INDEPENDENT",
    "REQUIRED_PRODUCTION_CONTROLS_MISSING"
}

ProductionControlRejectKinds == {
    "FIXTURE_CUSTODY",
    "NONPRODUCTION_CUSTODY",
    "HSM_UNAVAILABLE",
    "HSM_STALE",
    "INHIBIT_BLOCK",
    "INHIBIT_STOP",
    "INHIBIT_UNAVAILABLE",
    "INHIBIT_STALE",
    "INHIBIT_BINDING_MISMATCH",
    "INHIBIT_NOT_INDEPENDENT",
    "REQUIRED_PRODUCTION_CONTROLS_MISSING"
}

ControlRecords ==
    [snapshotA                    : MaybeBinding,
     snapshotB                    : MaybeBinding,
     proofBinding                 : MaybeBinding,
     proofAt                      : 0..MaxTime,
     proofConsumed                : BOOLEAN,
     prepareBinding               : MaybeBinding,
     prepareAt                    : 0..MaxTime,
     prepareConsumed              : BOOLEAN,
     custodyStatus                : CustodyStatuses,
     hsmAvailable                 : BOOLEAN,
     hsmAttestedAt                : 0..MaxTime,
     inhibitDecision              : InhibitDecisions,
     inhibitAvailable             : BOOLEAN,
     inhibitIndependent           : BOOLEAN,
     inhibitBinding               : MaybeBinding,
     inhibitObservedAt            : 0..MaxTime,
     commitBinding                : MaybeBinding,
     commitAt                     : 0..MaxTime,
     commitCount                  : 0..1,
     commitFromUnconsumedPrepare  : BOOLEAN,
     commitControlBinding         : MaybeBinding,
     commitHsmEvidenceAt          : 0..MaxTime,
     commitInhibitEvidenceAt      : 0..MaxTime,
     commitProductionCustodyOK    : BOOLEAN,
     commitIndependentInhibitOK   : BOOLEAN,
     authorityActive              : BOOLEAN,
     authorityOrigin              : AuthorityOrigins,
     leaseBinding                 : MaybeBinding,
     leaseIssuedAt                : 0..MaxTime,
     leaseRevoked                 : BOOLEAN,
     redemptionBinding            : MaybeBinding,
     redemptionAt                 : 0..MaxTime,
     redemptionCount              : 0..1,
     redemptionFromFreshLease     : BOOLEAN,
     redemptionControlBinding     : MaybeBinding,
     redemptionHsmEvidenceAt      : 0..MaxTime,
     redemptionInhibitEvidenceAt  : 0..MaxTime,
     redemptionProductionCustodyOK : BOOLEAN,
     redemptionIndependentInhibitOK : BOOLEAN,
     interlockBinding             : MaybeBinding,
     effectPermitBinding          : MaybeBinding,
     effectPermitAt               : 0..MaxTime,
     effectPermitHsmEvidenceAt    : 0..MaxTime,
     effectPermitInhibitEvidenceAt : 0..MaxTime,
     effectPermitProductionCustodyOK : BOOLEAN,
     effectPermitIndependentInhibitOK : BOOLEAN,
     effectBinding                : MaybeBinding,
     effectAt                     : 0..MaxTime,
     effectCount                  : 0..1,
     receiptBinding               : MaybeBinding,
     receiptAt                    : 0..MaxTime,
     continuationAllowed          : BOOLEAN,
     watchdogFailed               : BOOLEAN,
     blocked                      : BOOLEAN,
     rejections                   : SUBSET RejectKinds]

VARIABLES clock, ctl

vars == <<clock, ctl>>

InitRecord ==
    [snapshotA                   |-> NoBinding,
     snapshotB                   |-> NoBinding,
     proofBinding                |-> NoBinding,
     proofAt                     |-> 0,
     proofConsumed               |-> FALSE,
     prepareBinding              |-> NoBinding,
     prepareAt                   |-> 0,
     prepareConsumed             |-> FALSE,
     custodyStatus               |-> "UNASSESSED",
     hsmAvailable                |-> FALSE,
     hsmAttestedAt               |-> 0,
     inhibitDecision             |-> "NONE",
     inhibitAvailable            |-> FALSE,
     inhibitIndependent          |-> FALSE,
     inhibitBinding              |-> NoBinding,
     inhibitObservedAt           |-> 0,
     commitBinding               |-> NoBinding,
     commitAt                    |-> 0,
     commitCount                 |-> 0,
     commitFromUnconsumedPrepare |-> FALSE,
     commitControlBinding        |-> NoBinding,
     commitHsmEvidenceAt         |-> 0,
     commitInhibitEvidenceAt     |-> 0,
     commitProductionCustodyOK   |-> FALSE,
     commitIndependentInhibitOK  |-> FALSE,
     authorityActive             |-> FALSE,
     authorityOrigin             |-> "NONE",
     leaseBinding                |-> NoBinding,
     leaseIssuedAt               |-> 0,
     leaseRevoked                |-> FALSE,
     redemptionBinding           |-> NoBinding,
     redemptionAt                |-> 0,
     redemptionCount             |-> 0,
     redemptionFromFreshLease    |-> FALSE,
     redemptionControlBinding    |-> NoBinding,
     redemptionHsmEvidenceAt     |-> 0,
     redemptionInhibitEvidenceAt |-> 0,
     redemptionProductionCustodyOK |-> FALSE,
     redemptionIndependentInhibitOK |-> FALSE,
     interlockBinding            |-> NoBinding,
     effectPermitBinding         |-> NoBinding,
     effectPermitAt              |-> 0,
     effectPermitHsmEvidenceAt   |-> 0,
     effectPermitInhibitEvidenceAt |-> 0,
     effectPermitProductionCustodyOK |-> FALSE,
     effectPermitIndependentInhibitOK |-> FALSE,
     effectBinding               |-> NoBinding,
     effectAt                    |-> 0,
     effectCount                 |-> 0,
     receiptBinding              |-> NoBinding,
     receiptAt                   |-> 0,
     continuationAllowed         |-> FALSE,
     watchdogFailed              |-> FALSE,
     blocked                     |-> FALSE,
     rejections                  |-> {}]

Init ==
    /\ clock = 0
    /\ ctl = [t \in Traversals |-> InitRecord]

TypeOK ==
    /\ clock \in 0..MaxTime
    /\ ctl \in [Traversals -> ControlRecords]

EffectOf(binding) ==
    binding.effect

AdapterOf(binding) ==
    binding.adapter

NeedsProductionControls(binding) ==
    /\ binding \in Bindings
    /\ EffectOf(binding) \in HighestConsequenceEffects

ProductionCustodyReady(t) ==
    /\ ctl[t].custodyStatus = "PRODUCTION"
    /\ ctl[t].hsmAvailable
    /\ clock < ctl[t].hsmAttestedAt + HSMTTL

SafetyInhibitReady(t, binding) ==
    /\ binding \in Bindings
    /\ ctl[t].inhibitDecision = "CLEAR"
    /\ ctl[t].inhibitAvailable
    /\ ctl[t].inhibitIndependent
    /\ ctl[t].inhibitBinding = binding
    /\ clock < ctl[t].inhibitObservedAt + InhibitTTL

CurrentControlTarget(t) ==
    IF ctl[t].commitBinding \in Bindings
    THEN ctl[t].commitBinding
    ELSE ctl[t].prepareBinding

HighestConsequenceControlTarget(t) ==
    /\ CurrentControlTarget(t) \in Bindings
    /\ NeedsProductionControls(CurrentControlTarget(t))

LeaseFresh(t) ==
    /\ ctl[t].leaseBinding # NoBinding
    /\ ~ctl[t].leaseRevoked
    /\ clock < ctl[t].leaseIssuedAt + LeaseTTL

CommitReady(t) ==
    /\ ctl[t].commitCount = 0
    /\ ctl[t].prepareBinding # NoBinding
    /\ ~ctl[t].prepareConsumed
    /\ ~ctl[t].proofConsumed
    /\ ctl[t].snapshotA = ctl[t].snapshotB
    /\ ctl[t].snapshotA = ctl[t].proofBinding
    /\ ctl[t].proofBinding = ctl[t].prepareBinding
    /\ clock < ctl[t].proofAt + ProofTTL
    /\ clock < ctl[t].prepareAt + PrepareTTL

(***************************************************************************
 * Every rejected adversarial operation fails the traversal closed.  A
 * rejected input is recorded, but never installed in trusted binding state.
*)
FailClosed(t, kind, isWatchdogFailure) ==
    /\ kind \in RejectKinds
    /\ kind \notin ctl[t].rejections
    /\ ctl' = [ctl EXCEPT
         ![t].authorityActive = FALSE,
         ![t].leaseRevoked = TRUE,
         ![t].continuationAllowed = FALSE,
         ![t].watchdogFailed = @ \/ isWatchdogFailure,
         ![t].blocked = TRUE,
         ![t].rejections = @ \cup {kind}]
    /\ UNCHANGED clock

ObserveA(t, binding) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].snapshotA = NoBinding
    /\ binding \in Bindings
    /\ ctl' = [ctl EXCEPT ![t].snapshotA = binding]
    /\ UNCHANGED clock

ObserveB(t, binding) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].snapshotB = NoBinding
    /\ binding \in Bindings
    /\ ctl' = [ctl EXCEPT ![t].snapshotB = binding]
    /\ UNCHANGED clock

CertifyExactConvergence(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].proofBinding = NoBinding
    /\ ctl[t].snapshotA # NoBinding
    /\ ctl[t].snapshotA = ctl[t].snapshotB
    /\ ctl' = [ctl EXCEPT
         ![t].proofBinding = ctl[t].snapshotA,
         ![t].proofAt = clock]
    /\ UNCHANGED clock

Prepare(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding = NoBinding
    /\ ctl[t].proofBinding # NoBinding
    /\ ~ctl[t].proofConsumed
    /\ ctl[t].snapshotA = ctl[t].snapshotB
    /\ ctl[t].snapshotA = ctl[t].proofBinding
    /\ clock < ctl[t].proofAt + ProofTTL
    /\ ctl' = [ctl EXCEPT
         ![t].prepareBinding = ctl[t].proofBinding,
         ![t].prepareAt = clock]
    /\ UNCHANGED clock

AttestProductionCustody(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding \in Bindings
    /\ NeedsProductionControls(ctl[t].prepareBinding)
    /\ ctl[t].custodyStatus = "UNASSESSED"
    /\ ctl' = [ctl EXCEPT
         ![t].custodyStatus = "PRODUCTION",
         ![t].hsmAvailable = TRUE,
         ![t].hsmAttestedAt = clock]
    /\ UNCHANGED clock

ObserveIndependentSafetyInhibitClear(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding \in Bindings
    /\ NeedsProductionControls(ctl[t].prepareBinding)
    /\ ctl[t].inhibitDecision = "NONE"
    /\ ctl' = [ctl EXCEPT
         ![t].inhibitDecision = "CLEAR",
         ![t].inhibitAvailable = TRUE,
         ![t].inhibitIndependent = TRUE,
         ![t].inhibitBinding = ctl[t].prepareBinding,
         ![t].inhibitObservedAt = clock]
    /\ UNCHANGED clock

Commit(t) ==
    /\ ~ctl[t].blocked
    /\ CommitReady(t)
    /\ \/ ~NeedsProductionControls(ctl[t].prepareBinding)
       \/ /\ ProductionCustodyReady(t)
          /\ SafetyInhibitReady(t, ctl[t].prepareBinding)
    /\ ctl' = [ctl EXCEPT
         ![t].prepareConsumed = TRUE,
         ![t].proofConsumed = TRUE,
         ![t].commitBinding = ctl[t].prepareBinding,
         ![t].commitAt = clock,
         ![t].commitCount = 1,
         ![t].commitFromUnconsumedPrepare = TRUE,
         ![t].commitControlBinding = IF NeedsProductionControls(ctl[t].prepareBinding)
                                      THEN ctl[t].prepareBinding ELSE NoBinding,
         ![t].commitHsmEvidenceAt = ctl[t].hsmAttestedAt,
         ![t].commitInhibitEvidenceAt = ctl[t].inhibitObservedAt,
         ![t].commitProductionCustodyOK =
             NeedsProductionControls(ctl[t].prepareBinding),
         ![t].commitIndependentInhibitOK =
             NeedsProductionControls(ctl[t].prepareBinding),
         ![t].authorityActive = TRUE,
         ![t].authorityOrigin = "SOLE_COMMIT"]
    /\ UNCHANGED clock

IssueLease(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].authorityActive
    /\ ctl[t].commitCount = 1
    /\ ctl[t].leaseBinding = NoBinding
    /\ ctl' = [ctl EXCEPT
         ![t].leaseBinding = ctl[t].commitBinding,
         ![t].leaseIssuedAt = clock,
         ![t].leaseRevoked = FALSE]
    /\ UNCHANGED clock

RedeemAtPointOfUse(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].authorityActive
    /\ ctl[t].redemptionCount = 0
    /\ LeaseFresh(t)
    /\ ctl[t].leaseBinding = ctl[t].commitBinding
    /\ \/ ~NeedsProductionControls(ctl[t].leaseBinding)
       \/ /\ ProductionCustodyReady(t)
          /\ SafetyInhibitReady(t, ctl[t].leaseBinding)
    /\ ctl' = [ctl EXCEPT
         ![t].redemptionBinding = ctl[t].leaseBinding,
         ![t].redemptionAt = clock,
         ![t].redemptionCount = 1,
         ![t].redemptionFromFreshLease = TRUE,
         ![t].redemptionControlBinding =
             IF NeedsProductionControls(ctl[t].leaseBinding)
             THEN ctl[t].leaseBinding ELSE NoBinding,
         ![t].redemptionHsmEvidenceAt = ctl[t].hsmAttestedAt,
         ![t].redemptionInhibitEvidenceAt = ctl[t].inhibitObservedAt,
         ![t].redemptionProductionCustodyOK =
             NeedsProductionControls(ctl[t].leaseBinding),
         ![t].redemptionIndependentInhibitOK =
             NeedsProductionControls(ctl[t].leaseBinding)]
    /\ UNCHANGED clock

PassSafetyEnvelopeInterlock(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].redemptionCount = 1
    /\ ctl[t].interlockBinding = NoBinding
    /\ LeaseFresh(t)
    /\ ctl[t].redemptionBinding = ctl[t].leaseBinding
    /\ ctl[t].leaseBinding = ctl[t].commitBinding
    /\ EffectOf(ctl[t].leaseBinding) \in SafeEffects
    /\ clock = ctl[t].redemptionAt
    /\ ctl' = [ctl EXCEPT
         ![t].interlockBinding = ctl[t].redemptionBinding]
    /\ UNCHANGED clock

IssueFinalEffectPermit(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 0
    /\ ctl[t].effectPermitBinding = NoBinding
    /\ ctl[t].interlockBinding \in Bindings
    /\ NeedsProductionControls(ctl[t].interlockBinding)
    /\ ctl[t].interlockBinding = ctl[t].redemptionBinding
    /\ ctl[t].redemptionBinding = ctl[t].leaseBinding
    /\ ctl[t].leaseBinding = ctl[t].commitBinding
    /\ ProductionCustodyReady(t)
    /\ SafetyInhibitReady(t, ctl[t].interlockBinding)
    /\ ctl' = [ctl EXCEPT
         ![t].effectPermitBinding = ctl[t].interlockBinding,
         ![t].effectPermitAt = clock,
         ![t].effectPermitHsmEvidenceAt = ctl[t].hsmAttestedAt,
         ![t].effectPermitInhibitEvidenceAt = ctl[t].inhibitObservedAt,
         ![t].effectPermitProductionCustodyOK = TRUE,
         ![t].effectPermitIndependentInhibitOK = TRUE]
    /\ UNCHANGED clock

PerformEffect(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 0
    /\ ctl[t].interlockBinding # NoBinding
    /\ LeaseFresh(t)
    /\ ctl[t].commitBinding = ctl[t].leaseBinding
    /\ ctl[t].leaseBinding = ctl[t].redemptionBinding
    /\ ctl[t].redemptionBinding = ctl[t].interlockBinding
    /\ EffectOf(ctl[t].interlockBinding) \in SafeEffects
    /\ \/ ~NeedsProductionControls(ctl[t].interlockBinding)
       \/ /\ ctl[t].effectPermitBinding = ctl[t].interlockBinding
          /\ ctl[t].effectPermitProductionCustodyOK
          /\ ctl[t].effectPermitIndependentInhibitOK
          /\ clock = ctl[t].effectPermitAt
    /\ clock = ctl[t].redemptionAt
    /\ ctl' = [ctl EXCEPT
         ![t].effectBinding = ctl[t].interlockBinding,
         ![t].effectAt = clock,
         ![t].effectCount = 1]
    /\ UNCHANGED clock

AcceptSignedEffectReceipt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 1
    /\ ctl[t].receiptBinding = NoBinding
    /\ ~ctl[t].watchdogFailed
    /\ clock < ctl[t].leaseIssuedAt + LeaseTTL
    /\ clock < ctl[t].effectAt + WatchdogTTL
    /\ ctl' = [ctl EXCEPT
         ![t].receiptBinding = ctl[t].effectBinding,
         ![t].receiptAt = clock,
         ![t].continuationAllowed = TRUE]
    /\ UNCHANGED clock

Tick ==
    /\ clock < MaxTime
    /\ clock' = clock + 1
    /\ UNCHANGED ctl

(***************************************************************************
 * A fully fail-closed system is an intentional terminal condition, not an
 * operational deadlock.  Make its temporal stutter explicit so TLC's default
 * deadlock check agrees with [][Next]_vars without enabling any new behavior.
*)
FailClosedStutter ==
    /\ \A t \in Traversals : ctl[t].blocked
    /\ UNCHANGED vars

(***************************************************************************
 * Highest-consequence custody and independent SafetyInhibit failures.  The
 * external controls have no authority-granting transition: they can supply
 * evidence required by the sole COMMIT, or they can block/stop fail closed.
*)
FixtureCustodyAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "FIXTURE_CUSTODY", FALSE)

NonProductionCustodyAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "NONPRODUCTION_CUSTODY", FALSE)

HSMUnavailableAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "HSM_UNAVAILABLE", FALSE)

HSMStaleAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ ctl[t].custodyStatus = "PRODUCTION"
    /\ ctl[t].hsmAvailable
    /\ clock >= ctl[t].hsmAttestedAt + HSMTTL
    /\ FailClosed(t, "HSM_STALE", FALSE)

InhibitBlockAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "INHIBIT_BLOCK", FALSE)

InhibitStopAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "INHIBIT_STOP", FALSE)

InhibitUnavailableAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "INHIBIT_UNAVAILABLE", FALSE)

InhibitStaleAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ ctl[t].inhibitDecision = "CLEAR"
    /\ ctl[t].inhibitAvailable
    /\ ctl[t].inhibitIndependent
    /\ clock >= ctl[t].inhibitObservedAt + InhibitTTL
    /\ FailClosed(t, "INHIBIT_STALE", FALSE)

InhibitBindingMismatchAttempt(t, alteredBinding) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ alteredBinding \in Bindings
    /\ alteredBinding # CurrentControlTarget(t)
    /\ FailClosed(t, "INHIBIT_BINDING_MISMATCH", FALSE)

InhibitNotIndependentAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ HighestConsequenceControlTarget(t)
    /\ FailClosed(t, "INHIBIT_NOT_INDEPENDENT", FALSE)

MissingProductionControlsAtCommitAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].commitCount = 0
    /\ CommitReady(t)
    /\ NeedsProductionControls(ctl[t].prepareBinding)
    /\ ~(ProductionCustodyReady(t)
          /\ SafetyInhibitReady(t, ctl[t].prepareBinding))
    /\ FailClosed(t, "REQUIRED_PRODUCTION_CONTROLS_MISSING", FALSE)

MissingProductionControlsAtRedemptionAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].redemptionCount = 0
    /\ LeaseFresh(t)
    /\ NeedsProductionControls(ctl[t].leaseBinding)
    /\ ~(ProductionCustodyReady(t)
          /\ SafetyInhibitReady(t, ctl[t].leaseBinding))
    /\ FailClosed(t, "REQUIRED_PRODUCTION_CONTROLS_MISSING", FALSE)

MissingProductionControlsAtFinalPermitAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 0
    /\ ctl[t].effectPermitBinding = NoBinding
    /\ ctl[t].interlockBinding \in Bindings
    /\ NeedsProductionControls(ctl[t].interlockBinding)
    /\ ~(ProductionCustodyReady(t)
          /\ SafetyInhibitReady(t, ctl[t].interlockBinding))
    /\ FailClosed(t, "REQUIRED_PRODUCTION_CONTROLS_MISSING", FALSE)

(***************************************************************************
 * Explicit rejected transitions for divergence, replay, expiry, mutation,
 * adapter/effect mismatch, missing interlock and receipt/watchdog failures.
*)
DivergentConvergenceAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].snapshotA # NoBinding
    /\ ctl[t].snapshotB # NoBinding
    /\ ctl[t].snapshotA # ctl[t].snapshotB
    /\ FailClosed(t, "DIVERGENT_CONVERGENCE", FALSE)

PrepareWithoutExactProofAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding = NoBinding
    /\ \/ ctl[t].proofBinding = NoBinding
       \/ ctl[t].snapshotA # ctl[t].snapshotB
       \/ ctl[t].snapshotA # ctl[t].proofBinding
    /\ FailClosed(t, "PREPARE_WITHOUT_EXACT_PROOF", FALSE)

PrepareReplayAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding # NoBinding
    /\ FailClosed(t, "PREPARE_REPLAY", FALSE)

ExpiredProofAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].proofBinding # NoBinding
    /\ ~ctl[t].proofConsumed
    /\ clock >= ctl[t].proofAt + ProofTTL
    /\ FailClosed(t, "PROOF_EXPIRED", FALSE)

ExpiredPrepareAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].prepareBinding # NoBinding
    /\ ~ctl[t].prepareConsumed
    /\ clock >= ctl[t].prepareAt + PrepareTTL
    /\ FailClosed(t, "PREPARE_EXPIRED", FALSE)

MutationAttempt(t, alteredBinding) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].proofBinding # NoBinding
    /\ alteredBinding \in Bindings
    /\ alteredBinding # ctl[t].proofBinding
    /\ FailClosed(t, "MUTATED_BINDING", FALSE)

InvalidCommitAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].commitCount = 0
    /\ ~CommitReady(t)
    /\ FailClosed(t, "COMMIT_WITHOUT_MATCHING_PREPARE", FALSE)

CommitReplayAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].commitCount = 1
    /\ FailClosed(t, "COMMIT_REPLAY", FALSE)

LeaseBeforeCommitAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].commitCount = 0
    /\ FailClosed(t, "LEASE_BEFORE_COMMIT", FALSE)

ExpiredLeaseAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].leaseBinding # NoBinding
    /\ ctl[t].receiptBinding = NoBinding
    /\ clock >= ctl[t].leaseIssuedAt + LeaseTTL
    /\ FailClosed(t, "LEASE_EXPIRED", FALSE)

AdapterMismatchAttempt(t, alteredAdapter) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].leaseBinding # NoBinding
    /\ ctl[t].redemptionCount = 0
    /\ alteredAdapter \in Adapters
    /\ alteredAdapter # AdapterOf(ctl[t].leaseBinding)
    /\ FailClosed(t, "ADAPTER_MISMATCH", FALSE)

EffectMismatchAttempt(t, alteredEffect) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].leaseBinding # NoBinding
    /\ ctl[t].redemptionCount = 0
    /\ alteredEffect \in Effects
    /\ alteredEffect # EffectOf(ctl[t].leaseBinding)
    /\ FailClosed(t, "EFFECT_MISMATCH", FALSE)

RedemptionReplayAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].redemptionCount = 1
    /\ FailClosed(t, "REDEMPTION_REPLAY", FALSE)

SafetyEnvelopeBlock(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].redemptionCount = 1
    /\ ctl[t].interlockBinding = NoBinding
    /\ EffectOf(ctl[t].redemptionBinding) \notin SafeEffects
    /\ FailClosed(t, "SAFETY_ENVELOPE_BLOCK", FALSE)

EffectWithoutLeaseInterlockAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 0
    /\ \/ ctl[t].leaseBinding = NoBinding
       \/ ctl[t].redemptionCount = 0
       \/ ctl[t].interlockBinding = NoBinding
       \/ ctl[t].leaseBinding # ctl[t].redemptionBinding
       \/ ctl[t].redemptionBinding # ctl[t].interlockBinding
       \/ ctl[t].leaseRevoked
       \/ /\ NeedsProductionControls(ctl[t].interlockBinding)
          /\ ctl[t].effectPermitBinding # ctl[t].interlockBinding
    /\ FailClosed(t, "EFFECT_WITHOUT_LEASE_INTERLOCK", FALSE)

ReceiptBindingMismatchAttempt(t, alteredBinding) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 1
    /\ ctl[t].receiptBinding = NoBinding
    /\ alteredBinding \in Bindings
    /\ alteredBinding # ctl[t].effectBinding
    /\ FailClosed(t, "RECEIPT_BINDING_MISMATCH", TRUE)

InvalidReceiptSignatureAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 1
    /\ ctl[t].receiptBinding = NoBinding
    /\ FailClosed(t, "RECEIPT_SIGNATURE_INVALID", TRUE)

DuplicateReceiptAttempt(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].receiptBinding # NoBinding
    /\ FailClosed(t, "RECEIPT_DUPLICATE", TRUE)

WatchdogTimeout(t) ==
    /\ ~ctl[t].blocked
    /\ ctl[t].effectCount = 1
    /\ ctl[t].receiptBinding = NoBinding
    /\ clock >= ctl[t].effectAt + WatchdogTTL
    /\ FailClosed(t, "WATCHDOG_TIMEOUT", TRUE)

Next ==
    \/ Tick
    \/ FailClosedStutter
    \/ \E t \in Traversals, binding \in Bindings : ObserveA(t, binding)
    \/ \E t \in Traversals, binding \in Bindings : ObserveB(t, binding)
    \/ \E t \in Traversals : CertifyExactConvergence(t)
    \/ \E t \in Traversals : Prepare(t)
    \/ \E t \in Traversals : AttestProductionCustody(t)
    \/ \E t \in Traversals : ObserveIndependentSafetyInhibitClear(t)
    \/ \E t \in Traversals : Commit(t)
    \/ \E t \in Traversals : IssueLease(t)
    \/ \E t \in Traversals : RedeemAtPointOfUse(t)
    \/ \E t \in Traversals : PassSafetyEnvelopeInterlock(t)
    \/ \E t \in Traversals : IssueFinalEffectPermit(t)
    \/ \E t \in Traversals : PerformEffect(t)
    \/ \E t \in Traversals : AcceptSignedEffectReceipt(t)
    \/ \E t \in Traversals : DivergentConvergenceAttempt(t)
    \/ \E t \in Traversals : PrepareWithoutExactProofAttempt(t)
    \/ \E t \in Traversals : PrepareReplayAttempt(t)
    \/ \E t \in Traversals : ExpiredProofAttempt(t)
    \/ \E t \in Traversals : ExpiredPrepareAttempt(t)
    \/ \E t \in Traversals, binding \in Bindings : MutationAttempt(t, binding)
    \/ \E t \in Traversals : InvalidCommitAttempt(t)
    \/ \E t \in Traversals : CommitReplayAttempt(t)
    \/ \E t \in Traversals : LeaseBeforeCommitAttempt(t)
    \/ \E t \in Traversals : ExpiredLeaseAttempt(t)
    \/ \E t \in Traversals, adapter \in Adapters :
          AdapterMismatchAttempt(t, adapter)
    \/ \E t \in Traversals, effect \in Effects :
          EffectMismatchAttempt(t, effect)
    \/ \E t \in Traversals : RedemptionReplayAttempt(t)
    \/ \E t \in Traversals : SafetyEnvelopeBlock(t)
    \/ \E t \in Traversals : EffectWithoutLeaseInterlockAttempt(t)
    \/ \E t \in Traversals, binding \in Bindings :
          ReceiptBindingMismatchAttempt(t, binding)
    \/ \E t \in Traversals : InvalidReceiptSignatureAttempt(t)
    \/ \E t \in Traversals : DuplicateReceiptAttempt(t)
    \/ \E t \in Traversals : WatchdogTimeout(t)
    \/ \E t \in Traversals : FixtureCustodyAttempt(t)
    \/ \E t \in Traversals : NonProductionCustodyAttempt(t)
    \/ \E t \in Traversals : HSMUnavailableAttempt(t)
    \/ \E t \in Traversals : HSMStaleAttempt(t)
    \/ \E t \in Traversals : InhibitBlockAttempt(t)
    \/ \E t \in Traversals : InhibitStopAttempt(t)
    \/ \E t \in Traversals : InhibitUnavailableAttempt(t)
    \/ \E t \in Traversals : InhibitStaleAttempt(t)
    \/ \E t \in Traversals, binding \in Bindings :
          InhibitBindingMismatchAttempt(t, binding)
    \/ \E t \in Traversals : InhibitNotIndependentAttempt(t)
    \/ \E t \in Traversals : MissingProductionControlsAtCommitAttempt(t)
    \/ \E t \in Traversals : MissingProductionControlsAtRedemptionAttempt(t)
    \/ \E t \in Traversals : MissingProductionControlsAtFinalPermitAttempt(t)

Spec == Init /\ [][Next]_vars

(***************************************************************************
 * Required safety invariants and strengthening invariants.
*)
ProofCertifiesExactConvergence ==
    \A t \in Traversals :
        ctl[t].proofBinding # NoBinding =>
            /\ ctl[t].snapshotA = ctl[t].snapshotB
            /\ ctl[t].snapshotA = ctl[t].proofBinding

ExactConvergenceBeforePrepare ==
    \A t \in Traversals :
        ctl[t].prepareBinding # NoBinding =>
            /\ ctl[t].snapshotA = ctl[t].snapshotB
            /\ ctl[t].snapshotA = ctl[t].proofBinding
            /\ ctl[t].proofBinding = ctl[t].prepareBinding

PrepareIsNonAuthorizing ==
    \A t \in Traversals :
        (ctl[t].prepareBinding # NoBinding /\ ctl[t].commitCount = 0) =>
            ~ctl[t].authorityActive

NoAuthorityBeforeCommit ==
    \A t \in Traversals :
        ctl[t].authorityActive => ctl[t].commitCount = 1

CommitRequiresMatchingUnconsumedPrepare ==
    \A t \in Traversals :
        ctl[t].commitCount = 1 =>
            /\ ctl[t].commitFromUnconsumedPrepare
            /\ ctl[t].prepareConsumed
            /\ ctl[t].proofConsumed
            /\ ctl[t].commitBinding # NoBinding
            /\ ctl[t].commitBinding = ctl[t].prepareBinding
            /\ ctl[t].prepareBinding = ctl[t].proofBinding
            /\ ctl[t].proofBinding = ctl[t].snapshotA
            /\ ctl[t].snapshotA = ctl[t].snapshotB

AtMostOneCommitAndRedemptionPerTraversal ==
    \A t \in Traversals :
        /\ ctl[t].commitCount \in 0..1
        /\ ctl[t].redemptionCount \in 0..1
        /\ ctl[t].effectCount \in 0..1

NoEffectWithoutMatchingLeaseAndInterlock ==
    \A t \in Traversals :
        ctl[t].effectCount = 1 =>
            /\ ctl[t].commitCount = 1
            /\ ctl[t].redemptionCount = 1
            /\ ctl[t].redemptionFromFreshLease
            /\ ctl[t].effectBinding # NoBinding
            /\ ctl[t].effectBinding = ctl[t].commitBinding
            /\ ctl[t].commitBinding = ctl[t].leaseBinding
            /\ ctl[t].leaseBinding = ctl[t].redemptionBinding
            /\ ctl[t].redemptionBinding = ctl[t].interlockBinding
            /\ EffectOf(ctl[t].interlockBinding) \in SafeEffects
            /\ ctl[t].redemptionAt < ctl[t].leaseIssuedAt + LeaseTTL
            /\ ctl[t].effectAt < ctl[t].leaseIssuedAt + LeaseTTL
            /\ ctl[t].effectAt = ctl[t].redemptionAt

ExtensionAdmissionDisabledAndCarried ==
    \A t \in Traversals :
        /\ \A binding \in {
               ctl[t].snapshotA, ctl[t].snapshotB, ctl[t].proofBinding,
               ctl[t].prepareBinding, ctl[t].commitBinding,
               ctl[t].leaseBinding, ctl[t].redemptionBinding,
               ctl[t].interlockBinding, ctl[t].effectPermitBinding,
               ctl[t].effectBinding, ctl[t].receiptBinding
           } :
               binding # NoBinding =>
                   /\ binding.extensionAdmissionMode = "EXTENSIONS_DISABLED"
                   /\ binding.extensionSchema =
                          "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED"
        /\ (ctl[t].commitBinding # NoBinding =>
               ctl[t].commitBinding.extensionAdmissionBinding =
                   ctl[t].snapshotA.extensionAdmissionBinding)
        /\ (ctl[t].effectBinding # NoBinding =>
               ctl[t].effectBinding.extensionAdmissionBinding =
                   ctl[t].commitBinding.extensionAdmissionBinding)

HighestConsequenceCommitRequiresProductionControls ==
    \A t \in Traversals :
        (ctl[t].commitCount = 1
         /\ NeedsProductionControls(ctl[t].commitBinding)) =>
            /\ ctl[t].custodyStatus = "PRODUCTION"
            /\ ctl[t].commitProductionCustodyOK
            /\ ctl[t].commitIndependentInhibitOK
            /\ ctl[t].commitControlBinding = ctl[t].commitBinding
            /\ ctl[t].commitAt < ctl[t].commitHsmEvidenceAt + HSMTTL
            /\ ctl[t].commitAt <
               ctl[t].commitInhibitEvidenceAt + InhibitTTL

HighestConsequenceRedemptionRequiresProductionControls ==
    \A t \in Traversals :
        (ctl[t].redemptionCount = 1
         /\ NeedsProductionControls(ctl[t].redemptionBinding)) =>
            /\ ctl[t].custodyStatus = "PRODUCTION"
            /\ ctl[t].redemptionProductionCustodyOK
            /\ ctl[t].redemptionIndependentInhibitOK
            /\ ctl[t].redemptionControlBinding = ctl[t].redemptionBinding
            /\ ctl[t].redemptionAt <
               ctl[t].redemptionHsmEvidenceAt + HSMTTL
            /\ ctl[t].redemptionAt <
               ctl[t].redemptionInhibitEvidenceAt + InhibitTTL

HighestConsequenceEffectRequiresFinalPermit ==
    \A t \in Traversals :
        (ctl[t].effectCount = 1
         /\ NeedsProductionControls(ctl[t].effectBinding)) =>
            /\ ctl[t].effectPermitBinding = ctl[t].effectBinding
            /\ ctl[t].effectPermitBinding = ctl[t].interlockBinding
            /\ ctl[t].effectPermitProductionCustodyOK
            /\ ctl[t].effectPermitIndependentInhibitOK
            /\ ctl[t].effectPermitAt <
               ctl[t].effectPermitHsmEvidenceAt + HSMTTL
            /\ ctl[t].effectPermitAt <
               ctl[t].effectPermitInhibitEvidenceAt + InhibitTTL
            /\ ctl[t].effectAt = ctl[t].effectPermitAt

(***************************************************************************
 * Canonical validity is half-open: [issued, expiry).  These retained event
 * times make equality-at-expiry impossible to hide after an authorizing
 * transition has occurred.
*)
HalfOpenExpiryNeverAuthorizes ==
    \A t \in Traversals :
        /\ (ctl[t].commitCount = 1 =>
              /\ ctl[t].commitAt < ctl[t].proofAt + ProofTTL
              /\ ctl[t].commitAt < ctl[t].prepareAt + PrepareTTL)
        /\ (ctl[t].redemptionCount = 1 =>
              ctl[t].redemptionAt < ctl[t].leaseIssuedAt + LeaseTTL)
        /\ (ctl[t].effectCount = 1 =>
              ctl[t].effectAt < ctl[t].leaseIssuedAt + LeaseTTL)
        /\ (ctl[t].receiptBinding # NoBinding =>
              /\ ctl[t].receiptAt < ctl[t].leaseIssuedAt + LeaseTTL
              /\ ctl[t].receiptAt < ctl[t].effectAt + WatchdogTTL)

IndependentControlsCannotGrantOrWidenAuthority ==
    \A t \in Traversals :
        /\ ((ctl[t].authorityOrigin = "SOLE_COMMIT")
             <=> (ctl[t].commitCount = 1))
        /\ (ctl[t].authorityActive =>
              ctl[t].authorityOrigin = "SOLE_COMMIT")
        /\ (ctl[t].inhibitBinding # NoBinding =>
              ctl[t].inhibitBinding = ctl[t].prepareBinding)
        /\ (ctl[t].commitControlBinding # NoBinding =>
              ctl[t].commitControlBinding = ctl[t].commitBinding)
        /\ (ctl[t].redemptionControlBinding # NoBinding =>
              ctl[t].redemptionControlBinding = ctl[t].commitBinding)
        /\ (ctl[t].effectPermitBinding # NoBinding =>
              /\ ctl[t].effectPermitBinding = ctl[t].commitBinding
              /\ ctl[t].effectPermitBinding = ctl[t].interlockBinding)

ProductionControlFailureIsFailClosed ==
    \A t \in Traversals :
        ctl[t].rejections \cap ProductionControlRejectKinds # {} =>
            /\ ctl[t].blocked
            /\ ~ctl[t].authorityActive
            /\ ctl[t].leaseRevoked
            /\ ~ctl[t].continuationAllowed

WatchdogFailureBlocksContinuation ==
    \A t \in Traversals :
        ctl[t].watchdogFailed =>
            /\ ctl[t].blocked
            /\ ~ctl[t].authorityActive
            /\ ctl[t].leaseRevoked
            /\ ~ctl[t].continuationAllowed

ContinuationRequiresMatchingSignedReceipt ==
    \A t \in Traversals :
        ctl[t].continuationAllowed =>
            /\ ~ctl[t].blocked
            /\ ~ctl[t].watchdogFailed
            /\ ctl[t].effectCount = 1
            /\ ctl[t].receiptBinding = ctl[t].effectBinding
            /\ ctl[t].receiptBinding # NoBinding
            /\ ctl[t].receiptAt < ctl[t].leaseIssuedAt + LeaseTTL
            /\ ctl[t].receiptAt < ctl[t].effectAt + WatchdogTTL

FailClosedStateDisablesAuthority ==
    \A t \in Traversals :
        ctl[t].blocked =>
            /\ ~ctl[t].authorityActive
            /\ ctl[t].leaseRevoked
            /\ ~ctl[t].continuationAllowed

=============================================================================
