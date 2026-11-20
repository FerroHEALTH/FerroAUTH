- The federation field `trc.care_role` (`Field::TrcCareRole`): the care
  role a treatment relationship attests for the professional, one coded
  value with its code system, mapped from a claim, a credential subject, an
  attested `authorization_details` member or a `{ constant, system }`
  source like the other `trc.*` fields and read through `External::field`.
  A string, a code without a system or more than one code refuses the token
  as `Unclassified::Attribute` naming the field, and a contact point's
  token that carries it carries `trc.id` and both TRC window bounds.
