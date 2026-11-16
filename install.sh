#!/usr/bin/env bash
# Installs the RevEng.AI Ghidra plugin and enables it in the CodeBrowser tool.
#
#   curl -fsSL https://raw.githubusercontent.com/RevEngAI/plugin-ghidra/main/install.sh | bash
#
# GHIDRA_INSTALL_DIR  target this Ghidra install instead of detecting one
# REVENG_PLUGIN_VERSION  release tag to install (default: latest)
set -euo pipefail

REPO="RevEngAI/plugin-ghidra"
EXT_NAME="plugin-ghidra"
PLUGIN_PACKAGE="RevEng.AI"

die() { echo "error: $*" >&2; exit 1; }

for cmd in curl unzip; do
  command -v "$cmd" >/dev/null || die "'$cmd' is required"
done

case "$(uname -s)" in
  Darwin) SETTINGS_ROOT="$HOME/Library/ghidra" ;;
  *) SETTINGS_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/ghidra" ;;
esac

prop() { sed -n "s/^$1=//p" "$2/Ghidra/application.properties" | tr -d '\r'; }

find_installs() {
  local d
  {
    [ -f "$SETTINGS_ROOT/lastrun" ] && cat "$SETTINGS_ROOT/lastrun" && echo
    for d in /opt /usr/local /usr/share /usr/lib /Applications "$HOME" "$HOME/Downloads" \
      "$HOME/Desktop" "$HOME/tools" "$HOME/Applications" \
      /opt/homebrew/Caskroom/ghidra/* /usr/local/Caskroom/ghidra/*; do
      ls -d "$d"/[Gg]hidra* "$d"/[Gg]hidra*/[Gg]hidra* 2>/dev/null || true
    done
    ls -d /opt/homebrew/Cellar/ghidra/*/libexec /usr/local/Cellar/ghidra/*/libexec 2>/dev/null || true
  } | while IFS= read -r d; do
    [ -n "$d" ] && [ -f "$d/Ghidra/application.properties" ] && (cd -P "$d" && pwd)
  done | awk '!seen[$0]++'
}

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
  [ -f "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" ] || die "no Ghidra install at $GHIDRA_INSTALL_DIR"
  GHIDRA="$GHIDRA_INSTALL_DIR"
else
  INSTALLS=()
  while IFS= read -r d; do INSTALLS+=("$d"); done < <(find_installs)
  [ ${#INSTALLS[@]} -gt 0 ] || die "no Ghidra install found; set GHIDRA_INSTALL_DIR to its path"
  if [ ${#INSTALLS[@]} -eq 1 ]; then
    GHIDRA="${INSTALLS[0]}"
  else
    echo "Ghidra installs found:"
    for i in "${!INSTALLS[@]}"; do
      echo "  $((i + 1))) $(prop application.version "${INSTALLS[$i]}")  ${INSTALLS[$i]}"
    done
    # Read from the terminal: stdin is the script itself under `curl | bash`.
    read -rp "Install into [1-${#INSTALLS[@]}]: " choice </dev/tty || die "no terminal; set GHIDRA_INSTALL_DIR"
    [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#INSTALLS[@]} ] || die "invalid choice"
    GHIDRA="${INSTALLS[$((choice - 1))]}"
  fi
fi

VERSION="$(prop application.version "$GHIDRA")"
SETTINGS="$SETTINGS_ROOT/ghidra_${VERSION}_$(prop application.release.name "$GHIDRA")"
echo "Ghidra $VERSION at $GHIDRA"

if command -v pgrep >/dev/null && pgrep -f 'ghidra\.GhidraRun' >/dev/null; then
  die "Ghidra is running; close it and rerun"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ASSET="ghidra_${VERSION}_${EXT_NAME}.zip"
if [ -n "${REVENG_PLUGIN_VERSION:-}" ]; then
  URL="https://github.com/$REPO/releases/download/$REVENG_PLUGIN_VERSION/$ASSET"
else
  URL="https://github.com/$REPO/releases/latest/download/$ASSET"
fi
echo "Downloading $URL"
curl -fsSL -o "$TMP/$ASSET" "$URL" \
  || die "no release build for Ghidra $VERSION; see https://github.com/$REPO#building-your-own-plugin-for-custom-ghidra-forks-and-versions"

unzip -q "$TMP/$ASSET" -d "$TMP/x"
[ -f "$TMP/x/$EXT_NAME/extension.properties" ] || die "unexpected archive layout"
mkdir -p "$SETTINGS/Extensions"
rm -rf "${SETTINGS:?}/Extensions/$EXT_NAME"
mv "$TMP/x/$EXT_NAME" "$SETTINGS/Extensions/"
echo "Installed to $SETTINGS/Extensions/$EXT_NAME"

TOOL="$SETTINGS/tools/_code_browser.tcd"
if [ ! -f "$TOOL" ]; then
  echo "CodeBrowser not configured yet; Ghidra will offer to enable the plugins when it opens."
  exit 0
fi

PLUGINS="$(unzip -Z1 "$SETTINGS/Extensions/$EXT_NAME/lib/$EXT_NAME.jar" \
  | sed -n 's#^\(ai/reveng/toolkit/ghidra/plugins/[^/$]*Plugin\)\.class$#\1#p' | tr /'\n' '. ')"
[ -n "$PLUGINS" ] || die "no plugins found in $EXT_NAME.jar"

cp "$TOOL" "$TOOL.bak"
awk -v pkg="$PLUGIN_PACKAGE" -v plugins="$PLUGINS" '
  index($0, "<PACKAGE NAME=\"" pkg "\"") {
    if ($0 !~ /\/>/) skip = 1
    next
  }
  skip { if ($0 ~ /<\/PACKAGE>/) skip = 0; next }
  /<\/TOOL>/ && !done {
    print "        <PACKAGE NAME=\"" pkg "\">"
    n = split(plugins, p, " ")
    for (i = 1; i <= n; i++) print "            <INCLUDE CLASS=\"" p[i] "\" />"
    print "        </PACKAGE>"
    done = 1
  }
  { print }
' "$TOOL.bak" > "$TMP/tool.tcd"
mv "$TMP/tool.tcd" "$TOOL"
echo "Enabled in CodeBrowser (backup: $TOOL.bak)"
