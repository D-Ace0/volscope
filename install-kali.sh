#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="$project_dir/.venv"

python3 -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install --upgrade pip
"$venv_dir/bin/python" -m pip install -e "$project_dir"

launcher_dir="$HOME/.local/bin"
mkdir -p "$launcher_dir"
ln -sfn "$venv_dir/bin/volscope" "$launcher_dir/volscope"

case "${SHELL:-}" in
  */zsh) rc_file="$HOME/.zshrc" ;;
  */bash) rc_file="$HOME/.bashrc" ;;
  *)
    shell_name="$(ps -p "$PPID" -o comm= 2>/dev/null || true)"
    case "$shell_name" in
      *zsh*) rc_file="$HOME/.zshrc" ;;
      *) rc_file="$HOME/.bashrc" ;;
    esac
    ;;
esac

path_line='export PATH="$HOME/.local/bin:$PATH"'
if [[ ":$PATH:" != *":$launcher_dir:"* ]] && ! grep -Fqx "$path_line" "$rc_file" 2>/dev/null; then
  printf '\n# VolScope command\n%s\n' "$path_line" >> "$rc_file"
  echo "Added ~/.local/bin to $rc_file"
fi

echo "VolScope installed. Open a new terminal, then run: volscope"
