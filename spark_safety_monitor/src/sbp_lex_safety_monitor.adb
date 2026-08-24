package body SBP_Lex_Safety_Monitor is

   pragma SPARK_Mode (On);

   function Bounded_Future
     (Valid_Until : Tick;
      Now         : Tick;
      Limit       : Tick) return Boolean is
     (Now < Valid_Until and then Valid_Until - Now <= Limit);

   function Independent_Evidence
     (Custody : Custody_Attestation;
      Inhibit : Safety_Inhibit_Attestation) return Boolean is
     (Custody.Attestation_Digest /= Inhibit.Attestation_Digest);

   function Phase_Of (State : Monitor_State) return Phase_Kind is
     (State.Phase);

   function Failure_Of (State : Monitor_State) return Failure_Kind is
     (State.Failure);

   function Binding_Of (State : Monitor_State) return Execution_Binding is
     (State.Active_Binding);

   function Sequence_Of
     (State : Monitor_State) return Sequence_Number is
     (State.Last_Sequence);

   function Effect_Permit_Available
     (State : Monitor_State) return Boolean is
     (State.Effect_Permit_Flag);

   function Prepare_Proof_Consumed
     (State : Monitor_State) return Boolean is
     (State.Prepare_Consumed_Flag);

   function Lease_Consumed (State : Monitor_State) return Boolean is
     (State.Lease_Consumed_Flag);

   function Receipt_Deadline_Of (State : Monitor_State) return Tick is
     (State.Receipt_Deadline);

   function Authority_Key_Of (State : Monitor_State) return Digest is
     (State.Authority_Key_Id);

   function Invariant (State : Monitor_State) return Boolean is
     ((State.Phase = Fail_Closed) = (State.Failure /= No_Failure)
      and then
        State.Effect_Permit_Flag =
          (State.Phase = Point_Of_Use_Permitted)
      and then
        (if State.Phase = Idle then
           State.Active_Binding = Empty_Binding
           and then State.Prepare_Proof_Digest = Invalid_Digest
           and then State.Prepare_Valid_Until = 0
           and then not State.Prepare_Consumed_Flag
           and then State.Authority_Key_Id = Invalid_Digest
           and then State.Active_Lease_Id = Invalid_Digest
           and then State.Active_Lease_Digest = Invalid_Digest
           and then State.Lease_Valid_Until = 0
           and then not State.Lease_Consumed_Flag
           and then State.Effect_Permit_Digest = Invalid_Digest
           and then State.Effect_Permit_Until = 0
           and then State.Receipt_Deadline = 0
           and then State.Effect_Receipt_Digest = Invalid_Digest
           and then State.Last_Sequence = 0)
      and then
        (if State.Phase in Prepared .. Effect_Observed then
           Valid_Binding (State.Active_Binding)
           and then State.Prepare_Proof_Digest /= Invalid_Digest
           and then State.Prepare_Valid_Until > 0
           and then State.Last_Sequence > 0)
      and then
        (if State.Phase = Prepared then
           not State.Prepare_Consumed_Flag
           and then State.Authority_Key_Id = Invalid_Digest
           and then State.Active_Lease_Id = Invalid_Digest
           and then State.Active_Lease_Digest = Invalid_Digest
           and then State.Lease_Valid_Until = 0
           and then not State.Lease_Consumed_Flag
           and then State.Effect_Permit_Digest = Invalid_Digest
           and then State.Effect_Permit_Until = 0
           and then State.Receipt_Deadline = 0
           and then State.Effect_Receipt_Digest = Invalid_Digest)
      and then
        (if State.Phase in Committed .. Effect_Observed then
           State.Prepare_Consumed_Flag
           and then State.Authority_Key_Id /= Invalid_Digest)
      and then
        (if State.Phase = Committed then
           State.Active_Lease_Id = Invalid_Digest
           and then State.Active_Lease_Digest = Invalid_Digest
           and then State.Lease_Valid_Until = 0
           and then not State.Lease_Consumed_Flag
           and then State.Effect_Permit_Digest = Invalid_Digest
           and then State.Effect_Permit_Until = 0
           and then State.Receipt_Deadline = 0
           and then State.Effect_Receipt_Digest = Invalid_Digest)
      and then
        (if State.Phase in Lease_Issued .. Effect_Observed then
           State.Active_Lease_Id /= Invalid_Digest
           and then State.Active_Lease_Digest /= Invalid_Digest
           and then State.Lease_Valid_Until > 0)
      and then
        (if State.Phase = Lease_Issued then
           not State.Lease_Consumed_Flag
           and then State.Effect_Permit_Digest = Invalid_Digest
           and then State.Effect_Permit_Until = 0
           and then State.Receipt_Deadline = 0
           and then State.Effect_Receipt_Digest = Invalid_Digest)
      and then
        (if State.Phase in Point_Of_Use_Permitted .. Effect_Observed then
           State.Lease_Consumed_Flag
           and then State.Effect_Permit_Digest /= Invalid_Digest
           and then State.Effect_Permit_Until > 0)
      and then
        (if State.Phase = Point_Of_Use_Permitted then
           State.Receipt_Deadline = 0
           and then State.Effect_Receipt_Digest = Invalid_Digest)
      and then
        (if State.Phase in Effect_Dispatched .. Effect_Observed then
           State.Receipt_Deadline > 0
           and then State.Receipt_Deadline <= State.Effect_Permit_Until
           and then State.Receipt_Deadline <= State.Lease_Valid_Until)
      and then
        (if State.Phase = Effect_Dispatched then
           State.Effect_Receipt_Digest = Invalid_Digest)
      and then
        (if State.Phase = Effect_Observed then
           State.Effect_Receipt_Digest /= Invalid_Digest));

   function Fail_Closed_State
     (Current : Monitor_State;
      Failure : Failure_Kind) return Monitor_State
     with
       Pre  => Invariant (Current) and then Failure /= No_Failure,
       Post =>
         Invariant (Fail_Closed_State'Result)
         and then Is_Fail_Closed (Fail_Closed_State'Result)
         and then not Effect_Permit_Available
           (Fail_Closed_State'Result)
   is
      Result : Monitor_State := Current;
   begin
      Result.Phase := Fail_Closed;
      Result.Failure := Failure;
      Result.Effect_Permit_Flag := False;
      return Result;
   end Fail_Closed_State;

   function Initial_State return Monitor_State is
   begin
      return
        (Phase                 => Idle,
         Failure               => No_Failure,
         Active_Binding        => Empty_Binding,
         Prepare_Proof_Digest  => Invalid_Digest,
         Prepare_Valid_Until   => 0,
         Prepare_Consumed_Flag => False,
         Authority_Key_Id      => Invalid_Digest,
         Active_Lease_Id       => Invalid_Digest,
         Active_Lease_Digest   => Invalid_Digest,
         Lease_Valid_Until     => 0,
         Lease_Consumed_Flag   => False,
         Effect_Permit_Digest  => Invalid_Digest,
         Effect_Permit_Until   => 0,
         Effect_Permit_Flag    => False,
         Receipt_Deadline      => 0,
         Effect_Receipt_Digest => Invalid_Digest,
         Last_Sequence         => 0);
   end Initial_State;

   function Can_Prepare
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Exact_Convergence        : Boolean;
      Proof_Signature_Verified : Boolean;
      Proof_Digest             : Digest;
      Prepared_Until           : Tick;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Boolean is
     (Invariant (Current)
      and then Current.Phase = Idle
      and then Valid_Binding (Binding)
      and then Exact_Convergence
      and then Proof_Signature_Verified
      and then Proof_Digest /= Invalid_Digest
      and then Bounded_Future
        (Prepared_Until, Now, Max_Prepare_Lifetime)
      and then Proposed_Sequence > Current.Last_Sequence);

   function Apply_Prepare
     (Current                  : Monitor_State;
      Binding                  : Execution_Binding;
      Exact_Convergence        : Boolean;
      Proof_Signature_Verified : Boolean;
      Proof_Digest             : Digest;
      Prepared_Until           : Tick;
      Now                      : Tick;
      Proposed_Sequence        : Sequence_Number) return Monitor_State
   is
      Result : Monitor_State := Current;
   begin
      if not Can_Prepare
        (Current, Binding, Exact_Convergence, Proof_Signature_Verified,
         Proof_Digest, Prepared_Until, Now, Proposed_Sequence)
      then
         return Fail_Closed_State (Current, Prepare_Rejected);
      end if;

      Result.Phase := Prepared;
      Result.Active_Binding := Binding;
      Result.Prepare_Proof_Digest := Proof_Digest;
      Result.Prepare_Valid_Until := Prepared_Until;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Apply_Prepare;

   function Can_Commit
     (Current                      : Monitor_State;
      Binding                      : Execution_Binding;
      Proof_Digest                 : Digest;
      Authority_Signature_Verified : Boolean;
      Custody                      : Custody_Attestation;
      Inhibit                      : Safety_Inhibit_Attestation;
      Now                          : Tick;
      Proposed_Sequence            : Sequence_Number) return Boolean is
     (Invariant (Current)
      and then Current.Phase = Prepared
      and then Same_Binding (Current.Active_Binding, Binding)
      and then not Current.Prepare_Consumed_Flag
      and then Proof_Digest /= Invalid_Digest
      and then Proof_Digest = Current.Prepare_Proof_Digest
      and then Now < Current.Prepare_Valid_Until
      and then Authority_Signature_Verified
      and then Custody_Ready
        (Custody, Binding, Proposed_Sequence, Now)
      and then Inhibit_Ready
        (Inhibit, Binding, Custody.Key_Id, Proposed_Sequence, Now)
      and then Independent_Evidence (Custody, Inhibit)
      and then Proposed_Sequence > Current.Last_Sequence);

   function Apply_Commit
     (Current                      : Monitor_State;
      Binding                      : Execution_Binding;
      Proof_Digest                 : Digest;
      Authority_Signature_Verified : Boolean;
      Custody                      : Custody_Attestation;
      Inhibit                      : Safety_Inhibit_Attestation;
      Now                          : Tick;
      Proposed_Sequence            : Sequence_Number) return Monitor_State
   is
      Result : Monitor_State := Current;
   begin
      if not Can_Commit
        (Current, Binding, Proof_Digest, Authority_Signature_Verified,
         Custody, Inhibit, Now, Proposed_Sequence)
      then
         return Fail_Closed_State (Current, Commit_Rejected);
      end if;

      Result.Phase := Committed;
      Result.Prepare_Consumed_Flag := True;
      Result.Authority_Key_Id := Custody.Key_Id;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Apply_Commit;

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
      Proposed_Sequence        : Sequence_Number) return Boolean is
     (Invariant (Current)
      and then Current.Phase = Committed
      and then Same_Binding (Current.Active_Binding, Binding)
      and then Current.Prepare_Consumed_Flag
      and then Lease_Id /= Invalid_Digest
      and then Lease_Digest /= Invalid_Digest
      and then Lease_Signature_Verified
      and then Bounded_Future
        (Lease_Valid_Until, Now, Max_Lease_Lifetime)
      and then Custody_Ready
        (Custody, Binding, Proposed_Sequence, Now)
      and then Custody.Key_Id = Current.Authority_Key_Id
      and then Inhibit_Ready
        (Inhibit, Binding, Current.Authority_Key_Id,
         Proposed_Sequence, Now)
      and then Independent_Evidence (Custody, Inhibit)
      and then Proposed_Sequence > Current.Last_Sequence);

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
   is
      Result : Monitor_State := Current;
   begin
      if not Can_Issue_Lease
        (Current, Binding, Lease_Id, Lease_Digest,
         Lease_Signature_Verified, Lease_Valid_Until, Custody, Inhibit,
         Now, Proposed_Sequence)
      then
         return Fail_Closed_State (Current, Lease_Rejected);
      end if;

      Result.Phase := Lease_Issued;
      Result.Active_Lease_Id := Lease_Id;
      Result.Active_Lease_Digest := Lease_Digest;
      Result.Lease_Valid_Until := Lease_Valid_Until;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Issue_Lease;

   function Can_Redeem_At_Point_Of_Use
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
      Proposed_Sequence             : Sequence_Number) return Boolean is
     (Invariant (Current)
      and then Current.Phase = Lease_Issued
      and then Same_Binding (Current.Active_Binding, Binding)
      and then not Current.Lease_Consumed_Flag
      and then Lease_Id /= Invalid_Digest
      and then Lease_Id = Current.Active_Lease_Id
      and then Lease_Digest /= Invalid_Digest
      and then Lease_Digest = Current.Active_Lease_Digest
      and then Now < Current.Lease_Valid_Until
      and then Permit_Digest /= Invalid_Digest
      and then Capability_Signature_Verified
      and then Lease_Signature_Verified
      and then Safety_Envelope_Clear
      and then Bounded_Future
        (Permit_Valid_Until, Now, Max_Permit_Lifetime)
      and then Permit_Valid_Until <= Current.Lease_Valid_Until
      and then Custody_Ready
        (Custody, Binding, Proposed_Sequence, Now)
      and then Custody.Key_Id = Current.Authority_Key_Id
      and then Inhibit_Ready
        (Inhibit, Binding, Current.Authority_Key_Id,
         Proposed_Sequence, Now)
      and then Independent_Evidence (Custody, Inhibit)
      and then Proposed_Sequence > Current.Last_Sequence);

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
   is
      Result : Monitor_State := Current;
   begin
      if not Can_Redeem_At_Point_Of_Use
        (Current, Binding, Lease_Id, Lease_Digest, Permit_Digest,
         Capability_Signature_Verified, Lease_Signature_Verified,
         Safety_Envelope_Clear, Permit_Valid_Until, Custody, Inhibit,
         Now, Proposed_Sequence)
      then
         return Fail_Closed_State (Current, Redemption_Rejected);
      end if;

      Result.Phase := Point_Of_Use_Permitted;
      Result.Lease_Consumed_Flag := True;
      Result.Effect_Permit_Digest := Permit_Digest;
      Result.Effect_Permit_Until := Permit_Valid_Until;
      Result.Effect_Permit_Flag := True;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Redeem_At_Point_Of_Use;

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
      Proposed_Sequence         : Sequence_Number) return Boolean is
     (Invariant (Current)
      and then Current.Phase = Point_Of_Use_Permitted
      and then Same_Binding (Current.Active_Binding, Binding)
      and then Current.Lease_Consumed_Flag
      and then Current.Effect_Permit_Flag
      and then Permit_Digest /= Invalid_Digest
      and then Permit_Digest = Current.Effect_Permit_Digest
      and then Now < Current.Effect_Permit_Until
      and then Permit_Signature_Verified
      and then Safety_Envelope_Clear
       and then Bounded_Future
         (Receipt_Deadline, Now, Max_Receipt_Wait)
       and then Receipt_Deadline <= Current.Effect_Permit_Until
       and then Receipt_Deadline <= Current.Lease_Valid_Until
       and then Custody_Ready
        (Custody, Binding, Proposed_Sequence, Now)
      and then Custody.Key_Id = Current.Authority_Key_Id
      and then Inhibit_Ready
        (Inhibit, Binding, Current.Authority_Key_Id,
         Proposed_Sequence, Now)
      and then Independent_Evidence (Custody, Inhibit)
      and then Proposed_Sequence > Current.Last_Sequence);

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
   is
      Result : Monitor_State := Current;
   begin
      if not Can_Dispatch_Effect
        (Current, Binding, Permit_Digest, Permit_Signature_Verified,
         Safety_Envelope_Clear, Receipt_Deadline, Custody, Inhibit,
         Now, Proposed_Sequence)
      then
         return Fail_Closed_State (Current, Effect_Rejected);
      end if;

      Result.Phase := Effect_Dispatched;
      Result.Effect_Permit_Flag := False;
      Result.Receipt_Deadline := Receipt_Deadline;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Dispatch_Effect;

   function Record_Effect_Receipt
     (Current                    : Monitor_State;
      Binding                    : Execution_Binding;
      Receipt_Digest             : Digest;
      Receipt_Signature_Verified : Boolean;
      Effect_Observed_As_Bound    : Boolean;
      Now                        : Tick;
      Proposed_Sequence           : Sequence_Number) return Monitor_State
   is
      Result : Monitor_State := Current;
   begin
      if Current.Phase /= Effect_Dispatched
        or else not Same_Binding (Current.Active_Binding, Binding)
        or else Receipt_Digest = Invalid_Digest
        or else not Receipt_Signature_Verified
        or else not Effect_Observed_As_Bound
        or else Now >= Current.Receipt_Deadline
        or else Proposed_Sequence <= Current.Last_Sequence
      then
         return Fail_Closed_State (Current, Receipt_Rejected);
      end if;

      Result.Phase := Effect_Observed;
      Result.Effect_Receipt_Digest := Receipt_Digest;
      Result.Last_Sequence := Proposed_Sequence;
      return Result;
   end Record_Effect_Receipt;

   function Watchdog_Tick
     (Current : Monitor_State;
      Now     : Tick) return Monitor_State is
   begin
      if Current.Phase = Effect_Dispatched
        and then Now >= Current.Receipt_Deadline
      then
         return Fail_Closed_State (Current, Watchdog_Expired);
      end if;

      return Current;
   end Watchdog_Tick;

   function Observe_Safety_Inhibit
     (Current : Monitor_State;
      Inhibit : Safety_Inhibit_Attestation;
      Now     : Tick) return Monitor_State is
   begin
      if Current.Phase = Idle
        or else Current.Phase = Effect_Observed
        or else Current.Phase = Fail_Closed
      then
         return Current;
      elsif Inhibit_Ready
        (Inhibit, Current.Active_Binding, Current.Authority_Key_Id,
         Current.Last_Sequence, Now)
      then
         --  A Permit observation is deliberately a no-op.  Only the
         --  authority path above can advance the phase or create a permit.
         return Current;
      else
         return Fail_Closed_State (Current, Safety_Inhibit_Asserted);
      end if;
   end Observe_Safety_Inhibit;

end SBP_Lex_Safety_Monitor;
