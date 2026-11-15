# Open items

As of 2026-11-15. Close an item by moving its outcome into `HISTORY.md` (decisions) or `VERIFICATION.md` (checks), and
deleting it here.

## Packaging findings (2026-11-15), waiting for Zoltán

The other findings of the analysis are fixed (`HISTORY.md`).

1. **A Release build rewrites the published package files** (solution-wide). Every Release build of the solution writes
   the package of each project's current version into `..\.Documents\`, published or not. It happened on 2026-11-15: a
   build at 22:17:59 rewrote `Forge.Security.Jwt.Client.1.5.3.nupkg`, the file of the published version (the latest on
   nuget.org that day); it holds the new content now (`net11.0`, the icon …), not the published package. To restore it,
   download the published package from nuget.org; it carries nuget.org's repository signature, so it is not the uploaded
   file byte for byte. For the future, options: (b) packages only on request (`GeneratePackageOnBuild` off, `dotnet
   pack` per project when releasing); (c) the builds write their packages into another folder (for example
   `..\.Output\packages\`, unused since the post-build copy was commented out), and `..\.Documents\` keeps the published
   packages only, copied there when they are published. Recommendation: (c); the Release build stays as it is.

## Waiting for Zoltán

- **Publishing 1.6.1:** commit, then the Release build; the package depends on `Forge.Security.Jwt.Shared` 1.9.1, which
  is published before it.
- **The rules of `CLAUDE.md`** were carried over from `Forge.Next.Shared` and adapted on 2026-11-15; Zoltán has not
  reviewed them one by one.

## Not verified yet

- **No automated tests:** the behaviour on each target is not verified; `..\Testing.Security.Jwt` is a console harness.
- **The code review of 2026-02-03** (`..\CODE_REVIEW_REPORT.md`) lists for this package item 6
  (`Services/JwtTokenAuthenticationStateProvider.cs`: a race in the initialization of the refresh service); whether it
  was fixed since is not checked.
