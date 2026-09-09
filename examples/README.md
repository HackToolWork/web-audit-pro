# Examples

`targets.txt` and `scope.txt` are placeholders. Replace them only with systems you are explicitly authorized to assess.

For bug-bounty work, put the program's allowed hosts into `scope.txt` and use:

```bash
web-audit example.com --yes-i-am-authorized --scope-file examples/scope.txt
```
