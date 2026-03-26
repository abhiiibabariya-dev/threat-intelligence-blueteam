#!/bin/bash
# Safe save: shows what will be committed and asks for confirmation
set -e

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

echo "=== Unstaged/Untracked Changes ==="
git status --short

if [ -z "$(git status --porcelain)" ]; then
  echo "Nothing to save."
  exit 0
fi

echo ""
echo "=== Diff ==="
git diff --stat

echo ""
read -p "Stage all tracked changes and commit? [y/N] " confirm
if [[ "$confirm" != [yY] ]]; then
  echo "Aborted."
  exit 0
fi

read -p "Commit message: " msg
if [ -z "$msg" ]; then
  msg="WIP: checkpoint save $(date +%Y-%m-%d_%H:%M)"
fi

git add -u
git status --short
read -p "Push to remote? [y/N] " push_confirm
git commit -m "$msg"

if [[ "$push_confirm" == [yY] ]]; then
  git push
  echo "Pushed."
else
  echo "Committed locally (not pushed)."
fi
