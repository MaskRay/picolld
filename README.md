picolld (stripped-down lld)
===========================

With `llvm-config` in PATH,

```sh
mkdir out
cd out
cmake /path/to/picolld -G Ninja
ninja lld
```

Based on llvm-project/lld on 2020-04-10. Deleted

* MIPS: ~3000 lines
* LTO: ~800 lines
* basic block sections: ~400 lines

Removing the dependency on LLVM is possible, but it would require lots of efforts:

* `llvm/DebugInfo/DWARF/`: .eh_frame support
* `llvm/Object/`: ELF parsing
* `llvm/Option/Option.h`: command line parsing
* `llvm/ADT/`: STL extensions
