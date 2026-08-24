with SBP_Lex_Safety_Monitor;

procedure Spark_Safety_Monitor is
   --  This executable is a runtime assertion harness.  The reusable monitor
   --  package remains entirely in SPARK; keeping the harness out of proof
   --  avoids treating concrete test vectors as general verification goals.
   pragma SPARK_Mode (Off);

   use SBP_Lex_Safety_Monitor;

   Bound_Execution : constant Execution_Binding :=
     (Request => 11,
      State   => 12,
      Effect  => 13,
      Adapter => 14);

   Mutated_Execution : constant Execution_Binding :=
     (Request => 11,
      State   => 12,
      Effect  => 13,
      Adapter => 99);

   function Production_Custody
     (For_Sequence : Sequence_Number) return Custody_Attestation is
     (Provider           => Hardware_Security_Module,
       Key_Id             => 101,
       Attestation_Digest => 201,
       Binding            => Bound_Execution,
       Sequence           => For_Sequence,
       Issued_At          => 1,
       Valid_Until        => 20,
       Owner_Admitted     => True,
       Non_Exportable     => True,
       Signature_Verified => True,
      Available          => True);

   function Fixture_Custody
     (For_Sequence : Sequence_Number) return Custody_Attestation is
     (Provider           => Fixture_Provider,
       Key_Id             => 101,
       Attestation_Digest => 201,
       Binding            => Bound_Execution,
       Sequence           => For_Sequence,
       Issued_At          => 1,
       Valid_Until        => 20,
       Owner_Admitted     => True,
       Non_Exportable     => True,
       Signature_Verified => True,
      Available          => True);

   function Permit_Inhibit
     (For_Sequence : Sequence_Number)
      return Safety_Inhibit_Attestation is
     (Decision           => Permit,
       Controller_Id      => 102,
       Attestation_Digest => 202,
       Binding            => Bound_Execution,
       Sequence           => For_Sequence,
       Issued_At          => 1,
       Valid_Until        => 20,
       Owner_Admitted     => True,
       Signature_Verified => True,
      Available          => True);

   function Block_Inhibit
     (For_Sequence : Sequence_Number)
      return Safety_Inhibit_Attestation is
     (Decision           => Block,
       Controller_Id      => 102,
       Attestation_Digest => 202,
       Binding            => Bound_Execution,
       Sequence           => For_Sequence,
       Issued_At          => 1,
       Valid_Until        => 20,
       Owner_Admitted     => True,
       Signature_Verified => True,
      Available          => True);

   Current     : Monitor_State := Initial_State;
   Committed_S : Monitor_State := Initial_State;
   Leased_S    : Monitor_State := Initial_State;
   Permitted_S : Monitor_State := Initial_State;
   Dispatched_S : Monitor_State := Initial_State;
   Negative    : Monitor_State := Initial_State;
begin
   pragma Assert (Invariant (Current));
   pragma Assert (Phase_Of (Current) = Idle);
   pragma Assert (not Effect_Permit_Available (Current));

   Negative := Apply_Prepare
     (Current                  => Current,
      Binding                  => Bound_Execution,
      Exact_Convergence        => False,
      Proof_Signature_Verified => True,
      Proof_Digest             => 301,
      Prepared_Until           => 20,
      Now                      => 1,
      Proposed_Sequence        => 1);
   pragma Assert (Is_Fail_Closed (Negative));

   Current := Apply_Prepare
     (Current                  => Current,
      Binding                  => Bound_Execution,
      Exact_Convergence        => True,
      Proof_Signature_Verified => True,
      Proof_Digest             => 301,
      Prepared_Until           => 20,
      Now                      => 1,
      Proposed_Sequence        => 1);
   pragma Assert (Phase_Of (Current) = Prepared);
   pragma Assert (not Effect_Permit_Available (Current));

   Negative := Apply_Commit
     (Current                      => Current,
      Binding                      => Bound_Execution,
      Proof_Digest                 => 301,
      Authority_Signature_Verified => True,
      Custody                      => Fixture_Custody (2),
      Inhibit                      => Permit_Inhibit (2),
      Now                          => 2,
      Proposed_Sequence            => 2);
   pragma Assert (Is_Fail_Closed (Negative));

   Negative := Apply_Commit
     (Current                      => Current,
      Binding                      => Bound_Execution,
      Proof_Digest                 => 301,
      Authority_Signature_Verified => True,
      Custody                      => Production_Custody (1),
      Inhibit                      => Permit_Inhibit (1),
      Now                          => 2,
      Proposed_Sequence            => 2);
   pragma Assert (Is_Fail_Closed (Negative));

   Negative := Observe_Safety_Inhibit
     (Current => Current,
      Inhibit => Permit_Inhibit (1),
      Now     => 2);
   pragma Assert (Phase_Of (Negative) = Prepared);
   pragma Assert (not Effect_Permit_Available (Negative));

   Negative := Observe_Safety_Inhibit
     (Current => Current,
      Inhibit => Block_Inhibit (1),
      Now     => 2);
   pragma Assert (Is_Fail_Closed (Negative));

   Current := Apply_Commit
     (Current                      => Current,
      Binding                      => Bound_Execution,
      Proof_Digest                 => 301,
      Authority_Signature_Verified => True,
      Custody                      => Production_Custody (2),
      Inhibit                      => Permit_Inhibit (2),
      Now                          => 2,
      Proposed_Sequence            => 2);
   Committed_S := Current;
   pragma Assert (Phase_Of (Current) = Committed);
   pragma Assert (Prepare_Proof_Consumed (Current));
   pragma Assert (not Effect_Permit_Available (Current));

   Negative := Apply_Commit
     (Current                      => Current,
      Binding                      => Bound_Execution,
      Proof_Digest                 => 301,
      Authority_Signature_Verified => True,
      Custody                      => Production_Custody (3),
      Inhibit                      => Permit_Inhibit (3),
      Now                          => 2,
      Proposed_Sequence            => 3);
   pragma Assert (Is_Fail_Closed (Negative));

   Negative := Issue_Lease
     (Current                  => Committed_S,
      Binding                  => Bound_Execution,
      Lease_Id                 => 401,
      Lease_Digest             => 402,
      Lease_Signature_Verified => True,
      Lease_Valid_Until        => 9,
      Custody                  => Production_Custody (3),
      Inhibit                  => Permit_Inhibit (3),
      Now                      => 3,
      Proposed_Sequence        => 3);
   pragma Assert (Is_Fail_Closed (Negative));

   Current := Issue_Lease
     (Current                  => Current,
      Binding                  => Bound_Execution,
      Lease_Id                 => 401,
      Lease_Digest             => 402,
      Lease_Signature_Verified => True,
      Lease_Valid_Until        => 8,
      Custody                  => Production_Custody (3),
      Inhibit                  => Permit_Inhibit (3),
      Now                      => 3,
      Proposed_Sequence        => 3);
   Leased_S := Current;
   pragma Assert (Phase_Of (Current) = Lease_Issued);
   pragma Assert (not Lease_Consumed (Current));

   Negative := Redeem_At_Point_Of_Use
     (Current                       => Leased_S,
      Binding                       => Mutated_Execution,
      Lease_Id                      => 401,
      Lease_Digest                  => 402,
      Permit_Digest                 => 501,
      Capability_Signature_Verified => True,
      Lease_Signature_Verified      => True,
      Safety_Envelope_Clear         => True,
       Permit_Valid_Until            => 6,
      Custody                       => Production_Custody (4),
      Inhibit                       => Permit_Inhibit (4),
      Now                           => 4,
      Proposed_Sequence             => 4);
   pragma Assert (Is_Fail_Closed (Negative));

   Current := Redeem_At_Point_Of_Use
     (Current                       => Current,
      Binding                       => Bound_Execution,
      Lease_Id                      => 401,
      Lease_Digest                  => 402,
      Permit_Digest                 => 501,
      Capability_Signature_Verified => True,
      Lease_Signature_Verified      => True,
      Safety_Envelope_Clear         => True,
       Permit_Valid_Until            => 6,
      Custody                       => Production_Custody (4),
      Inhibit                       => Permit_Inhibit (4),
      Now                           => 4,
      Proposed_Sequence             => 4);
   Permitted_S := Current;
   pragma Assert (Phase_Of (Current) = Point_Of_Use_Permitted);
   pragma Assert (Lease_Consumed (Current));
   pragma Assert (Effect_Permit_Available (Current));

   Negative := Redeem_At_Point_Of_Use
     (Current                       => Permitted_S,
      Binding                       => Bound_Execution,
      Lease_Id                      => 401,
      Lease_Digest                  => 402,
      Permit_Digest                 => 501,
      Capability_Signature_Verified => True,
      Lease_Signature_Verified      => True,
      Safety_Envelope_Clear         => True,
      Permit_Valid_Until            => 6,
      Custody                       => Production_Custody (5),
      Inhibit                       => Permit_Inhibit (5),
      Now                           => 4,
      Proposed_Sequence             => 5);
   pragma Assert (Is_Fail_Closed (Negative));

   Negative := Dispatch_Effect
     (Current                   => Current,
      Binding                   => Bound_Execution,
      Permit_Digest             => 501,
      Permit_Signature_Verified => True,
      Safety_Envelope_Clear     => True,
      Receipt_Deadline          => 9,
      Custody                   => Production_Custody (5),
      Inhibit                   => Permit_Inhibit (5),
      Now                       => 5,
      Proposed_Sequence         => 5);
   pragma Assert (Is_Fail_Closed (Negative));
   pragma Assert (Failure_Of (Negative) = Effect_Rejected);

   Current := Dispatch_Effect
     (Current                   => Current,
      Binding                   => Bound_Execution,
      Permit_Digest             => 501,
      Permit_Signature_Verified => True,
      Safety_Envelope_Clear     => True,
       Receipt_Deadline          => 6,
      Custody                   => Production_Custody (5),
      Inhibit                   => Permit_Inhibit (5),
      Now                       => 5,
      Proposed_Sequence         => 5);
   Dispatched_S := Current;
   pragma Assert (Phase_Of (Current) = Effect_Dispatched);
   pragma Assert (not Effect_Permit_Available (Current));

   Negative := Dispatch_Effect
     (Current                   => Dispatched_S,
      Binding                   => Bound_Execution,
      Permit_Digest             => 501,
      Permit_Signature_Verified => True,
      Safety_Envelope_Clear     => True,
       Receipt_Deadline          => 6,
      Custody                   => Production_Custody (6),
      Inhibit                   => Permit_Inhibit (6),
      Now                       => 5,
      Proposed_Sequence         => 6);
   pragma Assert (Is_Fail_Closed (Negative));

   Negative := Watchdog_Tick
     (Current => Dispatched_S,
       Now     => 6);
   pragma Assert (Is_Fail_Closed (Negative));
   pragma Assert (Failure_Of (Negative) = Watchdog_Expired);

   Negative := Record_Effect_Receipt
     (Current                    => Dispatched_S,
      Binding                    => Bound_Execution,
      Receipt_Digest             => 601,
      Receipt_Signature_Verified => True,
      Effect_Observed_As_Bound    => True,
       Now                        => 6,
      Proposed_Sequence           => 6);
   pragma Assert (Is_Fail_Closed (Negative));
   pragma Assert (Failure_Of (Negative) = Receipt_Rejected);

   Current := Record_Effect_Receipt
     (Current                    => Dispatched_S,
      Binding                    => Bound_Execution,
      Receipt_Digest             => 601,
      Receipt_Signature_Verified => True,
      Effect_Observed_As_Bound    => True,
       Now                        => 5,
      Proposed_Sequence           => 6);
   pragma Assert (Phase_Of (Current) = Effect_Observed);
   pragma Assert (not Effect_Permit_Available (Current));
   pragma Assert (Invariant (Current));
end Spark_Safety_Monitor;
