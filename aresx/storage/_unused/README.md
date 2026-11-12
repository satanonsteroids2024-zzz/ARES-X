# aresx.storage/_unused
Dead-weight store files archived in v10. They had zero external callers:
- twin_store / mission_store / watchlist_store / evidence_vault_store / simulation_store
  were all "see store_modules.py" re-exports.
- store_modules.py implemented the CRUD helpers, also uncalled.
The canonical store is aresx.domains.twin.twin_store (used by the twin subsystems).
If a subsystem needs one of these helpers, implement it where needed instead of
reviving these modules.
