# Records docs/demo/files.gif from a real run: `vhs docs/demo/files.tape` from the repo root.
Output docs/demo/files.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 440
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

Hide
Type `export PS1='$ ' PATH=$PWD/target/release:$PATH && cargo build --release -q` Enter
Sleep 2s
Sleep 8s
Type `clear` Enter
Sleep 1s
Show
Type `agent-sandbox check --policy policies/coding-agent.toml --write /etc/hosts` Enter
Sleep 2s
Type `agent-sandbox check --policy policies/coding-agent.toml --read src/lib.rs` Enter
Sleep 2s
Type `agent-sandbox run --policy policies/coding-agent.toml --dry-run --json -- ls src | jq -c '.decision | {allowed, rule, reason}'` Enter
Sleep 3.5s
