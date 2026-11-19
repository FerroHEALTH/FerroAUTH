- A `[[ferrosmart.client]]` may register its app's `launch_uri`, and the
  EHR launch API takes `app_launch_uri` in place of `app_client_id`, so an
  EHR acting on a SMART `task-ehr-launch` Task, which names the app only by
  its launch URL, can register the launch. The URLs are compared after RFC
  3986 §6.2.2 normalization, and two clients may not register one (#659).
