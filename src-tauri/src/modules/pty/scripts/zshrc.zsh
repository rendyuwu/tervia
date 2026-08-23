# tervia-shell-integration (zshrc)
#
# Emits OSC 7 (cwd) + OSC 133 A/B/C/D (prompt-start / prompt-end / pre-exec /
# command-done-with-exit-code) so the host can detect command boundaries and
# track cwd without re-parsing the prompt. `status` is a read-only special in
# zsh, so we shadow $? into `_tervia_ret`.

{
  _tervia_user_zdotdir="${TERVIA_USER_ZDOTDIR:-$HOME}"
  [ -f "$_tervia_user_zdotdir/.zshrc" ] && source "$_tervia_user_zdotdir/.zshrc"
  unset _tervia_user_zdotdir
}

# Re-source guard within a single shell (e.g. user runs `source ~/.zshrc`).
# This is NOT exported, so each nested zsh installs its own hooks - desired,
# since every interactive shell needs its own prompt integration.
if [[ -z "$__TERVIA_HOOKS_LOADED" ]]; then
  __TERVIA_HOOKS_LOADED=1
  autoload -Uz add-zsh-hook 2>/dev/null

  # URL-encode $PWD byte-wise so multi-byte paths stay valid in the `file://`
  # URI emitted via OSC 7. `no_multibyte` forces ${s[i]} to index bytes (not
  # code points), and LC_ALL=C keeps the [a-zA-Z0-9...] class single-byte.
  _tervia_urlencode() {
    emulate -L zsh
    setopt localoptions no_multibyte
    local LC_ALL=C s="$1" i byte
    for (( i=1; i<=${#s}; i++ )); do
      byte="${s[i]}"
      case "$byte" in
        [a-zA-Z0-9/._~-]) printf '%s' "$byte" ;;
        *) printf '%%%02X' "'$byte" ;;
      esac
    done
  }

  _tervia_precmd() {
    local _tervia_ret=$?
    printf '\e]133;D;%s\e\\' "$_tervia_ret"
    printf '\e]7;file://%s%s\e\\' "${HOST}" "$(_tervia_urlencode "$PWD")"
    # Re-inject prompt-end marker in case a framework rebuilt PS1 (p10k, starship).
    if [[ "$PS1" != *$'\e]133;B\e\\'* ]]; then
      PS1=$'%{\e]133;B\e\\%}'"$PS1"
    fi
    printf '\e]133;A\e\\'
  }

  _tervia_preexec() {
    printf '\e]133;C\e\\'
  }

  if (( $+functions[add-zsh-hook] )); then
    add-zsh-hook precmd _tervia_precmd
    add-zsh-hook preexec _tervia_preexec
  fi

  # tervia_open: open file in editor tab via OSC 8888.
  # Usage: tervia_open <file>
  tervia_open() {
    local file="$1"

    if [[ -z "$file" ]]; then
      printf "usage: tervia_open <file>\n" >&2
      return 1
    fi

    # Resolve relative paths relative to PWD.
    if [[ "$file" != /* ]]; then
      file="$PWD/$file"
    fi

    # Check that the path exists and is a regular file.
    if [[ ! -f "$file" ]]; then
      printf "tervia_open: not a file: %s\n" "$file" >&2
      return 1
    fi

    # Emit OSC 8888 with URL-encoded file path.
    printf '\e]8888;file=%s\e\\' "$(_tervia_urlencode "$file")"
  }

  # Shorthand alias.
  alias tp='tervia_open'

  _tervia_precmd
fi
:
