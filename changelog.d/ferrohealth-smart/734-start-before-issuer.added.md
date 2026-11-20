- A product starts before its issuers are reachable: `IssuerSet::read_in_background`
  reads every issuer built with `ResourceServer::lazy` and not read yet, with
  a bounded back-off of one second doubling to one minute
  (`LazyResourceServer::read_until_read`), and `IssuerSet::is_ready` answers
  the product's readiness route, not ready until every issuer is read
  (`LazyResourceServer::is_read`). A configuration error still refuses the
  start.
