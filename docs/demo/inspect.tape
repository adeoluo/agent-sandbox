# Records docs/demo/inspect.gif from a real run: `vhs docs/demo/inspect.tape` from the repo root.
Output docs/demo/inspect.gif
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 620
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms

Hide
Type `export PS1='$ ' PATH=$PWD/target/release:$PATH && cargo build --release -q && clear` Enter
Sleep 10s
Show
Type `agent-sandbox inspect --policy policies/readonly.toml | head -n 22` Enter
Sleep 4s
