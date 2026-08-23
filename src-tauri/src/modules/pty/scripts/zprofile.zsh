# tervia-shell-integration (zprofile)
#
# See zshenv.zsh for the rationale on the trailing `:`.
{
  _tervia_user_zdotdir="${TERVIA_USER_ZDOTDIR:-$HOME}"
  [ -f "$_tervia_user_zdotdir/.zprofile" ] && source "$_tervia_user_zdotdir/.zprofile"
  unset _tervia_user_zdotdir
}
:
