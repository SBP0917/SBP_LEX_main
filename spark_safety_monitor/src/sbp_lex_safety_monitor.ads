pragma SPARK_Mode (On);

package SBP_Lex_Safety_Monitor is

   type Digest is mod 2 ** 64;
   Invalid_Digest : constant Digest := 0;

   subtype Tick is Long_Long_Integer range 0 .. Long_Long_Integer'Last;
   subtype Sequence_Number is Natural;

   Max_Attestation_Age    : constant Tick := 10;
   Max_Prepare_Lifetime   : constant Tick := 30;
   Max_Lease_Lifetime     : constant Tick := 5;
   Max_Permit_Lifetime    : constant Tick := 2;
   Max_Receipt_Wait       : constant Tick := 5;

   type Execution_Binding is record
      Request : Digest;
      State   : Digest;
      Effect  : Digest;
      Adapter : Digest;
   end record;

   type Phase_Kind is
     (Idle,
      Prepared,
      Committed,
      Lease_Issued,
      Point_Of_Use_Permitted,
      Effect_Dispatched,
      Effect_Observed,
      Fail_Closed);

   type Failure_Kind is
     (No_Failure,
      Prepare_Rejected,
      Commit_Rejected,
      Lease_Rejected,
      Redemption_Rejected,
      Effect_Rejected,
      Receipt_Rejected,
      Watchdog_Expired,
      Safety_Inhibit_Asserted);

   type Custody_Provider is
     (No_Provider,
      Fixture_Provider,
      Hardware_Security_Module,
      Trusted_Platform_Module);

   type Custody_Attestation is record
      Provider           : Custody_Provider;
      Key_Id             : Digest;
      Attestation_Digest : Digest;
      Binding            : Execution_Binding;
      Sequence           : Sequence_Number;
      Issued_At          : Tick;
      Valid_Until        : Tick;
      Owner_Admitted     : Boolean;
      Non_Exportable     : Boolean;
      Signature_Verified : Boolean;
      Available          : Boolean;
   end record;

   type Inhibit_Decision is (Inhibit_Unavailable, Block, Stop, Permit);

   type Safety_Inhibit_Attestation is record
      Decision           : Inhibit_Decision;
      Controller_Id      : Digest;
      Attestation_Digest : Digest;
      Binding            : Execution_Binding;
      Sequence           : Sequence_Number;
      Issued_At          : Tick;
      Valid_Until        : Tick;
      Owner_Admitted     : Boolean;
      Signature_Verified : Boolean;
      Available          : Boolean;
   end record;

   type Monitor_State is private;

   function Valid_Binding (Value : Execution_Binding) return Boolean is
     (Value.Request /= Invalid_Digest
      and then Value.State /= Invalid_Digest
      and then Value.Effect /= Invalid_Digest
      and then Value.Adapter /= Invalid_Digest);

   function Same_Binding
     (Left, Right : Execution_Binding) return Boolean is (Left = Right);

   function Custody_Ready
     (Custody           : Custody_Attestation;
      Binding           : Execution_Binding;
      Required_Sequence : Sequence_Number;
      Now               : Tick) return Boolean is
     ((Custody.Provider = Hardware_Security_Module
       or else Custody.Provider = Trusted_Platform_Module)
      and then Custody.Key_Id /= Invalid_Digest
      and then Custody.Attestation_Digest /= Invalid_Digest
      and then Same_Binding (Custody.Binding, Binding)
      and then Custody.Sequence = Required_Sequence
      and then Custody.Owner_Admitted
      and then Custody.Non_Exportable
      and then Custody.Signature_Verified
      and then Custody.Available
      and then Custody.Issued_At <= Now
      and then Now - Custody.Issued_At <= Max_Attestation_Age
      and then Now < Custody.Valid_Until);

   function Inhibit_Ready
     (Inhibit           : Safety_Inhibit_Attestation;
      Binding           : Execution_Binding;
      Authority_Key     : Digest;
      Required_Sequence : Sequence_Number;
      Now               : Tick) return Boolean is
     (Inhibit.Decision = Permit
      and then Inhibit.Controller_Id /= Invalid_Digest
      and then Inhibit.Controller_Id /= Authority_Key
      and then Inhibit.Attestation_Digest /= Invalid_Digest
      and then Same_Binding (Inhibit.Binding, Binding)
      and then Inhibit.Sequence = Required_Sequence
      and then Inhibit.Owner_Admitted
      and then Inhibit.Signature_Verified
      and then Inhibit.Available
      and then Inhibit.Issued_At <= Now
      and then Now - Inhibit.Issued_At <= Max_Attestation_Age
      and then Now < Inhibit.Valid_Until);

   function Phase_Of (State : Monitor_State) return Phase_Kind;
   function Failure_Of (State : Monitor_State) return Failure_Kind;
   function Binding_Of (State : Monitor_State) return Execution_Binding;
   function Sequence_Of (State : Monitor_State) return Sequence_Number;
   function Effect_Permit_Available
     (State : Monitor_State) return Boolean;
   function Prepare_Proof_Consumed
     (State : Monitor_State) return Boolean;
   function Lease_Consumed (State : Monitor_State) return Boolean;
   function Receipt_Deadline_Of (State : Monitor_State) return Tick;
   function Authority_Key_Of (State : Monitor_State) return Digest;
   function Is_Fail_Closed (State : Monitor_State) return Boolean is
     (Phase_Of (State) = Fail_Closed);
   function Invariant (State : Monitor_State) return Boolean;

   function Initial_State return Monitor_State
     with Post =>
       Invariant (Initial_State'Result)
       and then Phase_Of (Initial_State'Result) = Idle
       and then not Effect_Permit_Available (Initial_State'Result);

   function Can_Prepare
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Exact_Convergence        : Boolean;
      Proof_Signature_Verified : Boolean;
      Proof_Digest             : Digest;
      Prepared_Until           : Tick;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Boolean;

   function Apply_Prepare
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Exact_Convergence        : Boolean;
      Proof_Signature_Verified : Boolean;
      Proof_Digest             : Digest;
      Prepared_Until           : Tick;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Apply_Prepare'Result)
         and then not Effect_Permit_Available (Apply_Prepare'Result)
         and then
           (if Can_Prepare
              (Current, Binding, Exact_Convergence,
               Proof_Signature_Verified, Proof_Digest, Prepared_Until,
               Now, Proposed_Sequence)
            then Phase_Of (Apply_Prepare'Result) = Prepared
            else Is_Fail_Closed (Apply_Prepare'Result));

   function Can_Commit
     (Current                      : Monitor_State;
      Binding                      : Execution_Binding;
      Proof_Digest                 : Digest;
      Authority_Signature_Verified : Boolean;
      Custody                      : Custody_Attestation;
      Inhibit                      : Safety_Inhibit_Attestation;
      Now                          : Tick;
      Proposed_Sequence            : Sequence_Number) return Boolean;

   function Apply_Commit
     (Current                      : Monitor_State;
      Binding                      : Execution_Binding;
      Proof_Digest                 : Digest;
      Authority_Signature_Verified : Boolean;
      Custody                      : Custody_Attestation;
      Inhibit                      : Safety_Inhibit_Attestation;
      Now                          : Tick;
      Proposed_Sequence            : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Apply_Commit'Result)
         and then not Effect_Permit_Available (Apply_Commit'Result)
         and then
           (if Can_Commit
              (Current, Binding, Proof_Digest,
               Authority_Signature_Verified, Custody, Inhibit, Now,
               Proposed_Sequence)
            then Phase_Of (Apply_Commit'Result) = Committed
                 and then Prepare_Proof_Consumed (Apply_Commit'Result)
            else Is_Fail_Closed (Apply_Commit'Result));

   function Can_Issue_Lease
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Lease_Id                 : Digest;
      Lease_Digest             : Digest;
      Lease_Signature_Verified : Boolean;
      Lease_Valid_Until        : Tick;
      Custody                  : Custody_Attestation;
      Inhibit                  : Safety_Inhibit_Attestation;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Boolean;

   function Issue_Lease
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Lease_Id                 : Digest;
      Lease_Digest             : Digest;
      Lease_Signature_Verified : Boolean;
      Lease_Valid_Until        : Tick;
      Custody                  : Custody_Attestation;
      Inhibit                  : Safety_Inhibit_Attestation;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Issue_Lease'Result)
         and then not Effect_Permit_Available (Issue_Lease'Result)
         and then
           (if Can_Issue_Lease
              (Current, Binding, Lease_Id, Lease_Digest,
               Lease_Signature_Verified, Lease_Valid_Until,
               Custody, Inhibit, Now, Proposed_Sequence)
            then Phase_Of (Issue_Lease'Result) = Lease_Issued
                 and then not Lease_Consumed (Issue_Lease'Result)
            else Is_Fail_Closed (Issue_Lease'Result));

   function Can_Redeem_At_Point_Of_Use
     (Current                      : Monitor_State;
      Binding                      : Execution_Binding;
      Lease_Id                     : Digest;
      Lease_Digest                 : Digest;
      Permit_Digest                : Digest;
      Capability_Signature_Verified : Boolean;
      Lease_Signature_Verified     : Boolean;
      Safety_Envelope_Clear        : Boolean;
      Permit_Valid_Until           : Tick;
      Custody                      : Custody_Attestation;
      Inhibit                      : Safety_Inhibit_Attestation;
      Now                          : Tick;
      Proposed_Sequence            : Sequence_Number) return Boolean;

   function Redeem_At_Point_Of_Use
     (Current                       : Monitor_State;
      Binding                       : Execution_Binding;
      Lease_Id                      : Digest;
      Lease_Digest                  : Digest;
      Permit_Digest                 : Digest;
      Capability_Signature_Verified : Boolean;
      Lease_Signature_Verified      : Boolean;
      Safety_Envelope_Clear         : Boolean;
      Permit_Valid_Until            : Tick;
      Custody                       : Custody_Attestation;
      Inhibit                       : Safety_Inhibit_Attestation;
      Now                           : Tick;
      Proposed_Sequence             : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Redeem_At_Point_Of_Use'Result)
         and then
           (if Can_Redeem_At_Point_Of_Use
              (Current, Binding, Lease_Id, Lease_Digest, Permit_Digest,
               Capability_Signature_Verified, Lease_Signature_Verified,
               Safety_Envelope_Clear, Permit_Valid_Until, Custody,
               Inhibit, Now, Proposed_Sequence)
            then Phase_Of (Redeem_At_Point_Of_Use'Result) =
                   Point_Of_Use_Permitted
                 and then Effect_Permit_Available
                   (Redeem_At_Point_Of_Use'Result)
                 and then Lease_Consumed (Redeem_At_Point_Of_Use'Result)
            else Is_Fail_Closed (Redeem_At_Point_Of_Use'Result));

   function Can_Dispatch_Effect
     (Current                   : Monitor_State;
      Binding                   : Execution_Binding;
      Permit_Digest             : Digest;
      Permit_Signature_Verified : Boolean;
      Safety_Envelope_Clear     : Boolean;
      Receipt_Deadline          : Tick;
      Custody                   : Custody_Attestation;
      Inhibit                   : Safety_Inhibit_Attestation;
      Now                       : Tick;
      Proposed_Sequence         : Sequence_Number) return Boolean;

   function Dispatch_Effect
     (Current                   : Monitor_State;
      Binding                   : Execution_Binding;
      Permit_Digest             : Digest;
      Permit_Signature_Verified : Boolean;
      Safety_Envelope_Clear     : Boolean;
      Receipt_Deadline          : Tick;
      Custody                   : Custody_Attestation;
      Inhibit                   : Safety_Inhibit_Attestation;
      Now                       : Tick;
      Proposed_Sequence         : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Dispatch_Effect'Result)
         and then not Effect_Permit_Available (Dispatch_Effect'Result)
         and then
           (if Can_Dispatch_Effect
              (Current, Binding, Permit_Digest,
               Permit_Signature_Verified, Safety_Envelope_Clear,
               Receipt_Deadline, Custody, Inhibit, Now,
               Proposed_Sequence)
            then Phase_Of (Dispatch_Effect'Result) = Effect_Dispatched
            else Is_Fail_Closed (Dispatch_Effect'Result));

   function Record_Effect_Receipt
     (Current                    : Monitor_State;
      Binding                    : Execution_Binding;
      Receipt_Digest             : Digest;
      Receipt_Signature_Verified : Boolean;
      Effect_Observed_As_Bound    : Boolean;
      Now                        : Tick;
      Proposed_Sequence           : Sequence_Number) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Record_Effect_Receipt'Result)
         and then not Effect_Permit_Available
           (Record_Effect_Receipt'Result)
         and then
           (if Phase_Of (Current) = Effect_Dispatched
                and then Same_Binding (Binding_Of (Current), Binding)
                and then Receipt_Digest /= Invalid_Digest
                and then Receipt_Signature_Verified
                and then Effect_Observed_As_Bound
                and then Now < Receipt_Deadline_Of (Current)
                and then Proposed_Sequence > Sequence_Of (Current)
            then Phase_Of (Record_Effect_Receipt'Result) = Effect_Observed
            else Is_Fail_Closed (Record_Effect_Receipt'Result));

   function Watchdog_Tick
     (Current : Monitor_State;
      Now     : Tick) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Watchdog_Tick'Result)
         and then
           (if Phase_Of (Current) = Effect_Dispatched
                and then Now >= Receipt_Deadline_Of (Current)
            then Is_Fail_Closed (Watchdog_Tick'Result)
            else Watchdog_Tick'Result = Current);

   function Observe_Safety_Inhibit
     (Current : Monitor_State;
      Inhibit : Safety_Inhibit_Attestation;
      Now     : Tick) return Monitor_State
     with
       Pre  => Invariant (Current),
       Post =>
         Invariant (Observe_Safety_Inhibit'Result)
         and then
           (if Phase_Of (Current) = Idle
                or else Phase_Of (Current) = Effect_Observed
                or else Phase_Of (Current) = Fail_Closed
            then Observe_Safety_Inhibit'Result = Current
            elsif Inhibit_Ready
              (Inhibit, Binding_Of (Current), Authority_Key_Of (Current),
               Sequence_Of (Current), Now)
            then Observe_Safety_Inhibit'Result = Current
            else Is_Fail_Closed (Observe_Safety_Inhibit'Result));

private

   Empty_Binding : constant Execution_Binding :=
     (Request => Invalid_Digest,
      State   => Invalid_Digest,
      Effect  => Invalid_Digest,
      Adapter => Invalid_Digest);

   type Monitor_State is record
      Phase                  : Phase_Kind := Idle;
      Failure                : Failure_Kind := No_Failure;
      Active_Binding         : Execution_Binding := Empty_Binding;
      Prepare_Proof_Digest   : Digest := Invalid_Digest;
      Prepare_Valid_Until    : Tick := 0;
      Prepare_Consumed_Flag  : Boolean := False;
      Authority_Key_Id       : Digest := Invalid_Digest;
      Active_Lease_Id        : Digest := Invalid_Digest;
      Active_Lease_Digest    : Digest := Invalid_Digest;
      Lease_Valid_Until      : Tick := 0;
      Lease_Consumed_Flag    : Boolean := False;
      Effect_Permit_Digest   : Digest := Invalid_Digest;
      Effect_Permit_Until    : Tick := 0;
      Effect_Permit_Flag     : Boolean := False;
      Receipt_Deadline       : Tick := 0;
      Effect_Receipt_Digest  : Digest := Invalid_Digest;
      Last_Sequence          : Sequence_Number := 0;
   end record;

end SBP_Lex_Safety_Monitor;
