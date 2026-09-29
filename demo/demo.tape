# Records site/demo.gif. Needs the compose stack running. From the repo root:  vhs demo/demo.tape
Output site/demo.gif
Set FontSize 18
Set Width 1100
Set Height 620
Set Padding 24
Set TypingSpeed 35ms
Set Theme "Dracula"

Hide
Type ". demo/helpers.sh && clear" Enter
Sleep 300ms
Type "# The agent goes rogue. It only has a URL + key, no DB password." Enter
Type "rows" Enter
Sleep 500ms
Show
Sleep 1.2s
Type "agent 'DROP TABLE public.users'" Enter
Sleep 1.5s
Type "agent 'DELETE FROM public.users'" Enter
Sleep 1.5s
Type "agent 'DELETE FROM public.users WHERE id > 0'" Enter
Sleep 2s
Type "# A human approves it... and it was a mistake." Enter
Sleep 800ms
Type "human approve" Enter
Sleep 1.2s
Type "rows" Enter
Sleep 1.5s
Type "# Ctrl+Z:" Enter
Type "human undo" Enter
Sleep 1.2s
Type "rows" Enter
Sleep 3s
