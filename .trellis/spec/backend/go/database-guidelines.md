# Database

No database is implemented in the first offline planning slice. SQLite plus immutable filesystem evidence is the chosen CLI storage direction. Evaluate modernc.org/sqlite at the storage task; do not add a driver before migrations/transactions/recovery tests exist. Future SQL uses bound values and versioned migrations; no auto-upgrade of external production databases. PostgreSQL is deferred to the platform stage.
