------------------------------ MODULE SBPLEXV2 ------------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

(***************************************************************************
 * Bounded safety model for the SBP-LEX V2 single traversal.
 *
 * The stage order is derived from sbp_lex/config/pipeline_config.py and the
 * controlled local effect sequence in
 * sbp_lex/execution/controlled_local_adapter.py.  Cryptography, TPM behavior,
 * evidence semantics, and SHA-512 digest computation are abstract predicates
 * here. The model does not implement a hash function or format parser.
 * Every value other than the explicit value "VALID" fails closed.
 *************************************************************************)

CONSTANTS RequestIds, PermitIds, MaxRevocations, HostTPMAvailable

ASSUME /\ RequestIds # {}
       /\ PermitIds # {}
       /\ IsFiniteSet(RequestIds)
       /\ IsFiniteSet(PermitIds)
       /\ "NO_PERMIT" \notin PermitIds
       /\ MaxRevocations \in Nat \ {0}
       /\ HostTPMAvailable \in BOOLEAN

Entry                     == "entry"
StateConstruction         == "state_construction"
ThreePIngress             == "three_p_ingress"
CollectiveAttach          == "collective_attach"
RootAuthority             == "root_of_trust"
LicenceRootBinding        == "filed_licence_root_binding"
SKG                        == "skg_authority_constitutional_substrate"
ProceduralIntegrity       == "procedural_and_evidentiary_integrity"
PTODF                      == "filed_framework_ptodf"
Classification            == "classification"
LicenceValidation         == "filed_licence_validation"
Licensing                  == "licensing"
AJ_SAAF                    == "filed_framework_aj_saaf"
GovernanceDetermination    == "governance_determination"
GALA                       == "filed_framework_gala"
ABEGF                      == "filed_framework_abegf"
LifecycleObsolescence      == "filed_lifecycle_ai_obsolescence_supersession"
LifecycleSuccessor         == "filed_lifecycle_successor_intelligence_transition"
LifecyclePostAI            == "filed_lifecycle_structured_post_ai_continuity"
GovernanceFinal            == "governance"
GRC                        == "grc"
Domain                     == "domain_wrap"
AurionCandidate            == "aurion_candidate"
AurionTraversal            == "aurion_runtime"
LicenceRevalidation        == "filed_licence_revalidation"
TokenIssuance              == "token_issuance_and_chronology"
ExecutionGate              == "execution_gate"
PermitMint                 == "effect_permit_minting"
PermitClaim                == "effect_permit_claim"
ImmediateRevalidation      == "immediate_pre_effect_revalidation"
EffectDispatch             == "effect_dispatch"
AuditFinalization          == "audit_finalization"

StageOrder ==
    << Entry,
       StateConstruction,
       ThreePIngress,
       CollectiveAttach,
       RootAuthority,
       LicenceRootBinding,
       SKG,
       ProceduralIntegrity,
       PTODF,
       Classification,
       LicenceValidation,
       Licensing,
       AJ_SAAF,
       GovernanceDetermination,
       GALA,
       ABEGF,
       LifecycleObsolescence,
       LifecycleSuccessor,
       LifecyclePostAI,
       GovernanceFinal,
       GRC,
       Domain,
       AurionCandidate,
       AurionTraversal,
       LicenceRevalidation,
       TokenIssuance,
       ExecutionGate,
       PermitMint,
       PermitClaim,
       ImmediateRevalidation,
       EffectDispatch >>

Stages == {StageOrder[i] : i \in 1..Len(StageOrder)}

LifecycleStages ==
    {LifecycleObsolescence, LifecycleSuccessor, LifecyclePostAI}

MandatoryGovernanceStages ==
    {PTODF, AJ_SAAF, GovernanceDetermination, GALA, ABEGF,
     GovernanceFinal, GRC}

TokenPrerequisiteStages ==
    {RootAuthority, LicenceRootBinding, SKG, ProceduralIntegrity, PTODF,
     Classification, LicenceValidation, Licensing, AJ_SAAF,
     GovernanceDetermination, GALA, ABEGF, LifecycleObsolescence,
     LifecycleSuccessor, LifecyclePostAI, GovernanceFinal, Domain,
     AurionTraversal, LicenceRevalidation}

DecisionStages ==
    {ProceduralIntegrity, PTODF, Classification, Licensing, AJ_SAAF,
     GovernanceDetermination, GALA, ABEGF, LifecycleObsolescence,
     LifecycleSuccessor, LifecyclePostAI, GovernanceFinal, GRC, Domain,
     AurionCandidate, AurionTraversal, LicenceRevalidation, ExecutionGate}

SpecialStages ==
    {TokenIssuance, ExecutionGate, PermitMint, PermitClaim,
     ImmediateRevalidation, EffectDispatch}

EvidenceStatuses ==
    {"VALID", "INVALID", "UNKNOWN", "MALFORMED", "MISSING",
     "INDETERMINATE"}

FailClosedEvidence == EvidenceStatuses \ {"VALID"}
Modes == {"RUNNING", "TERMINAL_PENDING_AUDIT", "TERMINAL"}
Decisions == {"NONE", "APPROVED", "DENY", "ESCALATE", "HALT"}
FailureDecisions == {"DENY", "ESCALATE", "HALT"}
GovernanceOrigins == {"NONE", GovernanceDetermination}
AuditAttackKinds == {"NONE", "APPENDED_SUFFIX", "SUBSTITUTED_SUFFIX"}

NoStageEvidence == [st \in Stages |-> "UNSET"]
NoStageCount == [st \in Stages |-> 0]

VARIABLE state
vars == <<state>>

Init ==
    \E req \in RequestIds:
      state =
        [ mode                         |-> "RUNNING",
          nextIndex                    |-> 1,
          requestId                    |-> req,
          requestCount                 |-> 1,
          permitId                     |-> "NO_PERMIT",
          trace                        |-> <<>>,
          stageEvidence                |-> NoStageEvidence,
          threePEvidence               |-> NoStageEvidence,
          stageCount                   |-> NoStageCount,
          governanceStagePass          |-> {},
          lifecyclePass                |-> {},
          governanceAllow              |-> FALSE,
          governanceOrigin             |-> "NONE",
          lifecycleSupersededGovernance |-> FALSE,
          licenceValid                 |-> FALSE,
          revoked                      |-> FALSE,
          everRevoked                  |-> FALSE,
          revocationSequence           |-> 0,
          maxRevocationSeen            |-> 0,
          revocationRollbackAttempted  |-> FALSE,
          tokenValid                   |-> FALSE,
          tokenChronologyValid         |-> FALSE,
          tokenAuthority               |-> FALSE,
          executionGatePassed          |-> FALSE,
          permitValid                  |-> FALSE,
          permitCount                  |-> 0,
          permitConsumed               |-> FALSE,
          claimCount                   |-> 0,
          replayAttempted              |-> FALSE,
          replayRejected               |-> FALSE,
          immediateRevalidationValid   |-> FALSE,
          effectDispatched             |-> FALSE,
          effectCount                  |-> 0,
          receiptCount                 |-> 0,
          auditObligationCount         |-> 0,
          auditCount                   |-> 0,
          auditFinalized               |-> FALSE,
          auditCanonicalAccepted       |-> FALSE,
          auditSuffixAttackKind        |-> "NONE",
          decision                     |-> "NONE",
          decisionCount                |-> 0,
          decisionMade                 |-> FALSE,
          terminalFailure              |-> FALSE,
          unknownEvidenceObserved      |-> FALSE,
          bypassAttempted              |-> FALSE,
          lineageDecision              |-> "NONE",
          lineagePermit                |-> "NONE",
          lineageClaim                 |-> "NONE",
          lineageReceipt               |-> "NONE",
          lineageAudit                 |-> "NONE" ]

CurrentStage ==
    IF state.nextIndex <= Len(StageOrder)
    THEN StageOrder[state.nextIndex]
    ELSE AuditFinalization

Completed(st) == state.stageCount[st] = 1

Passed(st) ==
    /\ Completed(st)
    /\ state.stageEvidence[st] = "VALID"
    /\ state.threePEvidence[st] = "VALID"

AllPassed(stageSet) == \A st \in stageSet : Passed(st)

AppendValidStage(st) ==
    [state EXCEPT
       !.nextIndex = @ + 1,
       !.trace = Append(@, st),
       !.stageEvidence[st] = "VALID",
       !.threePEvidence[st] = "VALID",
       !.stageCount[st] = 1]

PassOrdinaryStage ==
    LET st == CurrentStage IN
      /\ state.mode = "RUNNING"
      /\ state.nextIndex <= Len(StageOrder)
      /\ st \notin SpecialStages
      /\ state' =
          [AppendValidStage(st) EXCEPT
             !.governanceStagePass =
                 IF st \in MandatoryGovernanceStages
                 THEN @ \cup {st}
                 ELSE @,
             !.lifecyclePass =
                 IF st \in LifecycleStages THEN @ \cup {st} ELSE @,
             !.governanceAllow =
                 IF st = GovernanceDetermination THEN TRUE ELSE @,
             !.governanceOrigin =
                 IF st = GovernanceDetermination
                 THEN GovernanceDetermination
                 ELSE @,
             !.licenceValid =
                 IF st \in {LicenceRootBinding, LicenceValidation,
                            LicenceRevalidation}
                 THEN TRUE
                 ELSE @]

EvidenceFailure ==
    \E p3 \in EvidenceStatuses, ev \in EvidenceStatuses:
      LET st == CurrentStage IN
        /\ state.mode = "RUNNING"
        /\ state.nextIndex <= Len(StageOrder)
        /\ ~(p3 = "VALID" /\ ev = "VALID")
        /\ state' =
            [state EXCEPT
               !.threePEvidence[st] = p3,
               !.stageEvidence[st] = ev,
               !.unknownEvidenceObserved = TRUE,
               !.mode = "TERMINAL_PENDING_AUDIT",
               !.decision = "HALT",
               !.decisionCount = 1,
               !.decisionMade = TRUE,
               !.terminalFailure = TRUE,
               !.licenceValid = FALSE,
               !.permitValid = FALSE,
               !.lineageDecision = state.requestId,
               !.lineageAudit = state.requestId,
               !.auditObligationCount = 1]

GovernedTermination ==
    \E outcome \in FailureDecisions:
      LET st == CurrentStage IN
        /\ state.mode = "RUNNING"
        /\ state.nextIndex <= Len(StageOrder)
        /\ st \in DecisionStages
        /\ state' =
            [AppendValidStage(st) EXCEPT
               !.mode = "TERMINAL_PENDING_AUDIT",
               !.decision = outcome,
               !.decisionCount = 1,
               !.decisionMade = TRUE,
               !.terminalFailure = TRUE,
               !.licenceValid = FALSE,
               !.permitValid = FALSE,
               !.lineageDecision = state.requestId,
               !.lineageAudit = state.requestId,
               !.auditObligationCount = 1]

IssueTokens ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = TokenIssuance
    /\ AllPassed(TokenPrerequisiteStages)
    /\ state' =
        [AppendValidStage(TokenIssuance) EXCEPT
           !.tokenValid = TRUE,
           !.tokenChronologyValid = TRUE,
           !.tokenAuthority = FALSE]

CanPassExecutionGate ==
    /\ AllPassed(MandatoryGovernanceStages)
    /\ AllPassed(LifecycleStages)
    /\ Passed(ThreePIngress)
    /\ Passed(RootAuthority)
    /\ Passed(SKG)
    /\ Passed(ProceduralIntegrity)
    /\ Passed(Domain)
    /\ Passed(AurionTraversal)
    /\ Passed(LicenceRevalidation)
    /\ state.governanceAllow
    /\ state.governanceOrigin = GovernanceDetermination
    /\ state.licenceValid
    /\ ~state.revoked
    /\ state.tokenValid
    /\ state.tokenChronologyValid
    /\ ~state.tokenAuthority

PassExecutionGate ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = ExecutionGate
    /\ CanPassExecutionGate
    /\ state' =
        [AppendValidStage(ExecutionGate) EXCEPT
           !.executionGatePassed = TRUE,
           !.decision = "APPROVED",
           !.decisionCount = 1,
           !.decisionMade = TRUE,
           !.lineageDecision = state.requestId]

MintPermit ==
    \E permit \in PermitIds:
      /\ state.mode = "RUNNING"
      /\ CurrentStage = PermitMint
      /\ HostTPMAvailable
      /\ state.executionGatePassed
      /\ state.decision = "APPROVED"
      /\ ~state.revoked
      /\ state.permitCount = 0
      /\ state' =
          [AppendValidStage(PermitMint) EXCEPT
             !.permitId = permit,
             !.permitValid = TRUE,
             !.permitCount = 1,
             !.lineagePermit = state.requestId]

TPMUnavailableFailClosed ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = PermitMint
    /\ ~HostTPMAvailable
    /\ state' =
        [state EXCEPT
           !.threePEvidence[PermitMint] = "VALID",
           !.stageEvidence[PermitMint] = "INDETERMINATE",
           !.unknownEvidenceObserved = TRUE,
           !.mode = "TERMINAL_PENDING_AUDIT",
           !.decision = "HALT",
           !.decisionMade = TRUE,
           !.terminalFailure = TRUE,
           !.licenceValid = FALSE,
           !.permitValid = FALSE,
           !.lineageAudit = state.requestId,
           !.auditObligationCount = 1]

ClaimPermit ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = PermitClaim
    /\ state.permitValid
    /\ state.permitCount = 1
    /\ ~state.permitConsumed
    /\ state.claimCount = 0
    /\ ~state.revoked
    /\ state' =
        [AppendValidStage(PermitClaim) EXCEPT
           !.permitConsumed = TRUE,
           !.claimCount = 1,
           !.lineageClaim = state.requestId]

ImmediatePreEffectRevalidation ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = ImmediateRevalidation
    /\ state.permitValid
    /\ state.permitConsumed
    /\ state.claimCount = 1
    /\ state.licenceValid
    /\ ~state.revoked
    /\ state.executionGatePassed
    /\ state' =
        [AppendValidStage(ImmediateRevalidation) EXCEPT
           !.immediateRevalidationValid = TRUE]

DispatchEffect ==
    /\ state.mode = "RUNNING"
    /\ CurrentStage = EffectDispatch
    /\ AllPassed(Stages \ {EffectDispatch})
    /\ state.executionGatePassed
    /\ state.decision = "APPROVED"
    /\ state.permitValid
    /\ state.permitCount = 1
    /\ state.permitConsumed
    /\ state.claimCount = 1
    /\ state.immediateRevalidationValid
    /\ state.licenceValid
    /\ ~state.revoked
    /\ state.effectCount = 0
    /\ state.receiptCount = 0
    /\ state' =
        [AppendValidStage(EffectDispatch) EXCEPT
           !.effectDispatched = TRUE,
           !.effectCount = 1,
           !.receiptCount = 1,
           !.mode = "TERMINAL_PENDING_AUDIT",
           !.lineageReceipt = state.requestId,
           !.lineageAudit = state.requestId,
           !.auditObligationCount = 1]

Revoke ==
    /\ state.mode = "RUNNING"
    /\ Completed(LicenceRootBinding)
    /\ ~state.revoked
    /\ state.revocationSequence < MaxRevocations
    /\ state' =
        [state EXCEPT
           !.revoked = TRUE,
           !.everRevoked = TRUE,
           !.revocationSequence = @ + 1,
           !.maxRevocationSeen = state.revocationSequence + 1,
           !.licenceValid = FALSE,
           !.permitValid = FALSE,
           !.mode = "TERMINAL_PENDING_AUDIT",
           !.decision = "HALT",
           !.decisionCount = 1,
           !.decisionMade = TRUE,
           !.terminalFailure = TRUE,
           !.lineageDecision = state.requestId,
           !.lineageAudit = state.requestId,
           !.auditObligationCount = 1]

AttemptRevocationRollback ==
    /\ state.everRevoked
    /\ ~state.revocationRollbackAttempted
    /\ state' =
        [state EXCEPT !.revocationRollbackAttempted = TRUE]

AttemptReplay ==
    /\ state.mode = "RUNNING"
    /\ state.permitConsumed
    /\ ~state.replayAttempted
    /\ state' =
        [state EXCEPT
           !.replayAttempted = TRUE,
           !.replayRejected = TRUE,
           !.permitValid = FALSE,
           !.licenceValid = FALSE,
           !.mode = "TERMINAL_PENDING_AUDIT",
           !.decision = "HALT",
           !.decisionMade = TRUE,
           !.terminalFailure = TRUE,
           !.lineageAudit = state.requestId,
           !.auditObligationCount = 1]

AttemptTraversalBypass ==
    \E attempted \in Stages \ {CurrentStage}:
      /\ state.mode = "RUNNING"
      /\ state.nextIndex <= Len(StageOrder)
      /\ state' =
          [state EXCEPT
             !.bypassAttempted = TRUE,
             !.mode = "TERMINAL_PENDING_AUDIT",
             !.decision = "HALT",
             !.decisionCount = 1,
             !.decisionMade = TRUE,
             !.terminalFailure = TRUE,
             !.licenceValid = FALSE,
             !.permitValid = FALSE,
             !.lineageDecision = state.requestId,
             !.lineageAudit = state.requestId,
             !.auditObligationCount = 1]

FinalizeAudit ==
    /\ state.mode = "TERMINAL_PENDING_AUDIT"
    /\ state.decisionMade
    /\ state.auditObligationCount = 1
    /\ state.auditCount = 0
    /\ state' =
        [state EXCEPT
           !.mode = "TERMINAL",
           !.auditCount = 1,
           !.auditFinalized = TRUE,
           !.auditCanonicalAccepted = TRUE,
           !.lineageAudit = state.requestId]

AttemptAuditSuffixAttack ==
    \E kind \in AuditAttackKinds \ {"NONE"}:
      /\ state.mode = "TERMINAL"
      /\ state.auditFinalized
      /\ state.auditSuffixAttackKind = "NONE"
      /\ state' =
          [state EXCEPT
             !.auditSuffixAttackKind = kind,
             !.auditCanonicalAccepted = FALSE]

Done ==
    /\ state.mode = "TERMINAL"
    /\ UNCHANGED state

Next ==
    \/ PassOrdinaryStage
    \/ EvidenceFailure
    \/ GovernedTermination
    \/ IssueTokens
    \/ PassExecutionGate
    \/ MintPermit
    \/ TPMUnavailableFailClosed
    \/ ClaimPermit
    \/ ImmediatePreEffectRevalidation
    \/ DispatchEffect
    \/ Revoke
    \/ AttemptRevocationRollback
    \/ AttemptReplay
    \/ AttemptTraversalBypass
    \/ FinalizeAudit
    \/ AttemptAuditSuffixAttack
    \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(FinalizeAudit)

(***************************************************************************
 * Type and structure invariant used by TLC in addition to the 22 required
 * security invariants below.
 *************************************************************************)
TypeOK ==
    /\ state.mode \in Modes
    /\ state.nextIndex \in 1..(Len(StageOrder) + 1)
    /\ state.requestId \in RequestIds
    /\ state.requestCount \in 0..1
    /\ state.permitId \in PermitIds \cup {"NO_PERMIT"}
    /\ state.trace \in Seq(Stages)
    /\ state.stageEvidence \in [Stages -> EvidenceStatuses \cup {"UNSET"}]
    /\ state.threePEvidence \in [Stages -> EvidenceStatuses \cup {"UNSET"}]
    /\ state.stageCount \in [Stages -> 0..1]
    /\ state.governanceStagePass \subseteq MandatoryGovernanceStages
    /\ state.lifecyclePass \subseteq LifecycleStages
    /\ state.governanceAllow \in BOOLEAN
    /\ state.governanceOrigin \in GovernanceOrigins
    /\ state.lifecycleSupersededGovernance \in BOOLEAN
    /\ state.licenceValid \in BOOLEAN
    /\ state.revoked \in BOOLEAN
    /\ state.everRevoked \in BOOLEAN
    /\ state.revocationSequence \in 0..MaxRevocations
    /\ state.maxRevocationSeen \in 0..MaxRevocations
    /\ state.revocationRollbackAttempted \in BOOLEAN
    /\ state.tokenValid \in BOOLEAN
    /\ state.tokenChronologyValid \in BOOLEAN
    /\ state.tokenAuthority \in BOOLEAN
    /\ state.executionGatePassed \in BOOLEAN
    /\ state.permitValid \in BOOLEAN
    /\ state.permitCount \in 0..1
    /\ state.permitConsumed \in BOOLEAN
    /\ state.claimCount \in 0..1
    /\ state.replayAttempted \in BOOLEAN
    /\ state.replayRejected \in BOOLEAN
    /\ state.immediateRevalidationValid \in BOOLEAN
    /\ state.effectDispatched \in BOOLEAN
    /\ state.effectCount \in 0..1
    /\ state.receiptCount \in 0..1
    /\ state.auditObligationCount \in 0..1
    /\ state.auditCount \in 0..1
    /\ state.auditFinalized \in BOOLEAN
    /\ state.auditCanonicalAccepted \in BOOLEAN
    /\ state.auditSuffixAttackKind \in AuditAttackKinds
    /\ state.decision \in Decisions
    /\ state.decisionCount \in 0..1
    /\ state.decisionMade \in BOOLEAN
    /\ state.terminalFailure \in BOOLEAN
    /\ state.unknownEvidenceObserved \in BOOLEAN
    /\ state.bypassAttempted \in BOOLEAN
    /\ state.lineageDecision \in RequestIds \cup {"NONE"}
    /\ state.lineagePermit \in RequestIds \cup {"NONE"}
    /\ state.lineageClaim \in RequestIds \cup {"NONE"}
    /\ state.lineageReceipt \in RequestIds \cup {"NONE"}
    /\ state.lineageAudit \in RequestIds \cup {"NONE"}

Inv01_NoEffectWithoutSatisfiedThreeP ==
    state.effectDispatched => \A st \in Stages :
        state.threePEvidence[st] = "VALID"

Inv02_NoEffectWithoutAuthenticatedSKG ==
    state.effectDispatched => Passed(SKG)

Inv03_NoEffectWithoutValidAuthorityState ==
    state.effectDispatched => Passed(RootAuthority) /\ Passed(LicenceRootBinding)

Inv04_NoEffectWithoutMandatoryGovernance ==
    state.effectDispatched =>
        /\ AllPassed(MandatoryGovernanceStages)
        /\ state.governanceStagePass = MandatoryGovernanceStages
        /\ state.governanceAllow

Inv05_NoEffectWithoutThreeLifecycleStages ==
    state.effectDispatched =>
        /\ AllPassed(LifecycleStages)
        /\ state.lifecyclePass = LifecycleStages

Inv06_NoEffectWithoutValidActiveLicence ==
    state.effectDispatched => state.licenceValid /\ ~state.revoked

Inv07_NoEffectAfterRevocation ==
    state.effectDispatched => ~state.revoked /\ ~state.everRevoked

Inv08_NoEffectWithoutCompleteTokenChronology ==
    state.effectDispatched =>
        /\ state.tokenValid
        /\ state.tokenChronologyValid
        /\ Passed(TokenIssuance)

Inv09_NoEffectWithoutValidPermit ==
    state.effectDispatched =>
        /\ state.permitValid
        /\ state.permitCount = 1
        /\ state.permitId \in PermitIds

Inv10_NoEffectWithoutImmediateRevalidation ==
    state.effectDispatched =>
        /\ state.immediateRevalidationValid
        /\ Passed(ImmediateRevalidation)

Inv11_OnlyGovernanceDeterminationCreatesAllow ==
    state.governanceAllow =>
        /\ state.governanceOrigin = GovernanceDetermination
        /\ Completed(GovernanceDetermination)

Inv12_NoTokenIndependentlyGrantsExecution ==
    /\ ~state.tokenAuthority
    /\ (state.effectDispatched => state.executionGatePassed)

Inv13_NoLifecycleSupersedesGovernance ==
    /\ ~state.lifecycleSupersededGovernance
    /\ (state.governanceAllow =>
          state.governanceOrigin = GovernanceDetermination)

Inv14_NoFailedMandatoryStageBypassed ==
    state.effectDispatched => AllPassed(Stages)

Inv15_TerminalFailurePreventsLaterExecution ==
    state.terminalFailure =>
        /\ state.mode # "RUNNING"
        /\ ~state.effectDispatched
        /\ state.effectCount = 0

Inv16_RevocationIsMonotonic ==
    /\ state.maxRevocationSeen = state.revocationSequence
    /\ (state.everRevoked =>
          /\ state.revoked
          /\ state.revocationSequence > 0
          /\ ~state.licenceValid
          /\ ~state.permitValid)

Inv17_ConsumedPermitsCannotBeReplayed ==
    /\ state.claimCount <= 1
    /\ (state.permitConsumed => state.claimCount = 1)
    /\ (state.replayAttempted =>
          /\ state.replayRejected
          /\ state.effectCount = 0)

Inv18_StagesCannotSkipDuplicateOrReorder ==
    /\ Len(state.trace) <= Len(StageOrder)
    /\ \A i \in 1..Len(state.trace) : state.trace[i] = StageOrder[i]
    /\ \A st \in Stages :
          state.stageCount[st] =
            Cardinality({i \in 1..Len(state.trace) : state.trace[i] = st})

Inv19_AuditAfterTerminalDecision ==
    state.auditFinalized =>
        /\ state.decisionMade
        /\ state.decision # "NONE"
        /\ state.mode = "TERMINAL"
        /\ (state.terminalFailure \/ state.effectDispatched)
        /\ state.auditCount = 1
        /\ state.auditObligationCount = 1

Inv20_AuditSuffixCannotBecomeCanonical ==
    state.auditSuffixAttackKind # "NONE" =>
        /\ state.auditFinalized
        /\ ~state.auditCanonicalAccepted

Inv21_UnknownEvidenceCannotReachExecution ==
    state.effectDispatched =>
        /\ ~state.unknownEvidenceObserved
        /\ \A st \in Stages :
             /\ state.stageEvidence[st] = "VALID"
             /\ state.threePEvidence[st] = "VALID"

Inv22_EffectHasExactlyOneTraceableLineage ==
    state.effectDispatched =>
        /\ state.requestCount = 1
        /\ state.decisionCount = 1
        /\ state.permitCount = 1
        /\ state.claimCount = 1
        /\ state.effectCount = 1
        /\ state.receiptCount = 1
        /\ state.auditObligationCount = 1
        /\ state.auditCount <= 1
        /\ state.lineageDecision = state.requestId
        /\ state.lineagePermit = state.requestId
        /\ state.lineageClaim = state.requestId
        /\ state.lineageReceipt = state.requestId
        /\ state.lineageAudit = state.requestId
        /\ (state.auditFinalized => state.auditCount = 1)

=============================================================================
