# Records docs/demo/sandbox.gif from a real run: `vhs docs/demo/sandbox.tape` (after cargo build --release).
Output docs/demo/sandbox.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 560
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type "export PS1='$ ' PATH=$PWD/target/release:$PATH && rm -f /tmp/demo-audit.jsonl && clear" Enter
Show
Type "agent-sandbox check --policy policies/coding-agent.toml -- cat ~/.ssh/id_ed25519" Enter
Sleep 1.5s
Type "agent-sandbox check --policy policies/coding-agent.toml -- curl https://example.com" Enter
Sleep 1.5s
Type "agent-sandbox run --policy policies/coding-agent.toml --audit /tmp/demo-audit.jsonl -- ls src" Enter
Sleep 2s
Type "agent-sandbox audit verify /tmp/demo-audit.jsonl" Enter
Sleep 3s
