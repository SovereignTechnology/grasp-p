# Work Directory

Use this directory for session notes, investigation reports, deployment checks,
soak results, plans, and temporary analysis files. Everything except this README
is ignored by Git.

Keep operational reports here; do not commit them. Use descriptive filenames
or dated subdirectories so retained evidence is easy to find. Delete obsolete
files when they are no longer needed.

Write lasting product documentation directly in the appropriate directory under
`docs/`: tutorials, how-to guides, reference, or explanation. Permanent docs
should not link to ignored working files.

```gitignore
work/*
!work/README.md
```
