# Sourced in the test derivation; all paths belong to its private sandbox.
mkdir -p "$HOME/hostile-git/hooks" "$HOME/hostile-git/template/hooks"
printf '#!/bin/sh\necho "hostile hook: ambient git config leaked into a test" >&2\nexit 1\n' \
  | tee "$HOME/hostile-git/hooks/pre-commit" > "$HOME/hostile-git/template/hooks/pre-commit"
chmod +x "$HOME/hostile-git/hooks/pre-commit" "$HOME/hostile-git/template/hooks/pre-commit"
git config --global init.defaultBranch main
git config --global core.hooksPath "$HOME/hostile-git/hooks"
git config --global init.templateDir "$HOME/hostile-git/template"
git config --global commit.gpgsign true
git config --global core.autocrlf true
