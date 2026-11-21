- FerroSMART runs on PostgreSQL 19 and refuses to start against an older
  server, naming the `server_version_num` it found and the 190000 it needs.
  The quickstart and the CI store run `postgres:19.0`. PostgreSQL 18 is no
  longer supported and there is no upgrade path: a quickstart volume holding
  an 18 cluster is removed and created again.
