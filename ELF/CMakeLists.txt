set(LLVM_TARGET_DEFINITIONS Options.td)
tablegen(LLVM Options.inc -gen-opt-parser-defs)
add_public_tablegen_target(ELFOptionsTableGen)

if(NOT LLD_BUILT_STANDALONE)
  set(tablegen_deps intrinsics_gen)
endif()

add_lld_library(lldELF
  Arch/AArch64.cpp
  Arch/ARM.cpp
  Arch/PPC.cpp
  Arch/PPC64.cpp
  Arch/RISCV.cpp
  Arch/X86.cpp
  Arch/X86_64.cpp
  DWARF.cpp
  Driver.cpp
  DriverUtils.cpp
  EhFrame.cpp
  ICF.cpp
  InputFiles.cpp
  InputSection.cpp
  LinkerScript.cpp
  MapFile.cpp
  MarkLive.cpp
  OutputSections.cpp
  Relocations.cpp
  ScriptLexer.cpp
  ScriptParser.cpp
  SymbolTable.cpp
  Symbols.cpp
  SyntheticSections.cpp
  Target.cpp
  Thunks.cpp
  Writer.cpp

  LINK_COMPONENTS
  Object
  Option
  Support

  LINK_LIBS
  lldCommon
  ${LLVM_PTHREAD_LIB}

  DEPENDS
  ELFOptionsTableGen
  ${tablegen_deps}
  )
