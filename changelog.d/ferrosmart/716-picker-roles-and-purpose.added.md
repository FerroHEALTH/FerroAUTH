- The patient picker's token carries the person's `roles`, and an openEHR
  `[[ferrosmart.resource]]` may list the purposes of use its server accepts
  (`[[ferrosmart.resource.purpose]]`, with `purpose_header`, default
  `x-purpose-of-use`). A professional chooses one on the picker page, the
  EHR lookup and the look-up-again of the choice declare it in that header,
  the request keeps it so the two cannot differ, and each lookup's access
  record names it (`purposeOfEvent`). A patient's own lookup declares none.
