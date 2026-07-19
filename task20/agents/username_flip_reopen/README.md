# Username flip re-open

This is a bounded live check of the newly supplied `admim` -> `admin` idea.
The earlier local scan covered offsets around -396; this probe tests the
exact lifecycle-derived candidates -0x55c and -0x4fc only. It uses a fresh FTP
child per attempt, records raw replies, PWD/NLST, and RETR results, and never
claims a key unless the server returns the exact `avito{...}` value.
