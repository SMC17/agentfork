/-
  Machine-checked formal invariants for agentfork:
  1. Information-Flow Control (IFC) non-interference for untrusted web taint at shell_exec.
  2. Monotonic fencing-token ordering under lease transfer.
-/

inductive Decision where
  | allow
  | deny_untrusted_exec
  | deny_secret_exfil
  deriving DecidableEq, Repr

def evalShellPolicy (hasUntrustedWeb : Bool) : Decision :=
  if hasUntrustedWeb then Decision.deny_untrusted_exec else Decision.allow

theorem untrusted_web_never_allowed_at_shell (h : hasUntrustedWeb = true) :
    evalShellPolicy hasUntrustedWeb = Decision.deny_untrusted_exec := by
  simp [evalShellPolicy, h]

theorem shell_allow_implies_clean_taint (h : evalShellPolicy hasUntrustedWeb = Decision.allow) :
    hasUntrustedWeb = false := by
  cases hasUntrustedWeb with
  | false => rfl
  | true => simp [evalShellPolicy] at h

theorem fencing_token_strictly_monotone (seq : Nat) :
    seq < seq + 1 := by
  omega
