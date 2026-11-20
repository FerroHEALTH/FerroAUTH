- Breaking: a token of an issuer whose metadata or key set has not been read
  since the start is refused as the new `Rejection::Unread`, `503` with the
  reason code `issuer-unread` (`Reason::IssuerUnread`), in place of
  `Rejection::Unavailable`. A product that matches `Rejection` exhaustively
  adds the variant.
