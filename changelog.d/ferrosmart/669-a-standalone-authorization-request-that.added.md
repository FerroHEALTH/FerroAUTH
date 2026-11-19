- A standalone authorization request that asks a `patient/` scope without
  `launch/patient` is read as asking `launch/patient`, so the patient picker
  supplies the patient instead of the `patient/` scopes being dropped, and
  the granted `scope` names the inferred `launch/patient` (SMART App Launch
  2.2.0, Scopes and Launch Context, Standalone apps) (#669).
