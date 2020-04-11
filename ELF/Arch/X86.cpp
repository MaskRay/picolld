//===- X86.cpp ------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "InputFiles.h"
#include "Symbols.h"
#include "SyntheticSections.h"
#include "Target.h"
#include "lld/Common/ErrorHandler.h"
#include "llvm/Support/Endian.h"

using namespace llvm;
using namespace llvm::support::endian;
using namespace llvm::ELF;

namespace lld {
namespace elf {

namespace {
class X86 : public TargetInfo {
public:
  X86();
  int getTlsGdRelaxSkip(RelType type) const override;
  RelExpr getRelExpr(RelType type, const Symbol &s,
                     const uint8_t *loc) const override;
  int64_t getImplicitAddend(const uint8_t *buf, RelType type) const override;
  void writeGotPltHeader(uint8_t *buf) const override;
  RelType getDynRel(RelType type) const override;
  void writeGotPlt(uint8_t *buf, const Symbol &s) const override;
  void writeIgotPlt(uint8_t *buf, const Symbol &s) const override;
  void writePltHeader(uint8_t *buf) const override;
  void writePlt(uint8_t *buf, const Symbol &sym,
                uint64_t pltEntryAddr) const override;
  void relocate(uint8_t *loc, const Relocation &rel,
                uint64_t val) const override;

  RelExpr adjustRelaxExpr(RelType type, const uint8_t *data,
                          RelExpr expr) const override;
  void relaxTlsGdToIe(uint8_t *loc, const Relocation &rel,
                      uint64_t val) const override;
  void relaxTlsGdToLe(uint8_t *loc, const Relocation &rel,
                      uint64_t val) const override;
  void relaxTlsIeToLe(uint8_t *loc, const Relocation &rel,
                      uint64_t val) const override;
  void relaxTlsLdToLe(uint8_t *loc, const Relocation &rel,
                      uint64_t val) const override;
};
} // namespace

X86::X86() {
  copyRel = R_386_COPY;
  gotRel = R_386_GLOB_DAT;
  noneRel = R_386_NONE;
  pltRel = R_386_JUMP_SLOT;
  iRelativeRel = R_386_IRELATIVE;
  relativeRel = R_386_RELATIVE;
  symbolicRel = R_386_32;
  tlsGotRel = R_386_TLS_TPOFF;
  tlsModuleIndexRel = R_386_TLS_DTPMOD32;
  tlsOffsetRel = R_386_TLS_DTPOFF32;
  pltHeaderSize = 16;
  pltEntrySize = 16;
  ipltEntrySize = 16;
  trapInstr = {0xcc, 0xcc, 0xcc, 0xcc}; // 0xcc = INT3

  // Align to the non-PAE large page size (known as a superpage or huge page).
  // FreeBSD automatically promotes large, superpage-aligned allocations.
  defaultImageBase = 0x400000;
}

int X86::getTlsGdRelaxSkip(RelType type) const {
  return 2;
}

RelExpr X86::getRelExpr(RelType type, const Symbol &s,
                        const uint8_t *loc) const {
  // There are 4 different TLS variable models with varying degrees of
  // flexibility and performance. LocalExec and InitialExec models are fast but
  // less-flexible models. If they are in use, we set DF_STATIC_TLS flag in the
  // dynamic section to let runtime know about that.
  if (type == R_386_TLS_LE || type == R_386_TLS_LE_32 || type == R_386_TLS_IE ||
      type == R_386_TLS_GOTIE)
    config->hasStaticTlsModel = true;

  switch (type) {
  case R_386_8:
  case R_386_16:
  case R_386_32:
    return R_ABS;
  case R_386_TLS_LDO_32:
    return R_DTPREL;
  case R_386_TLS_GD:
    return R_TLSGD_GOTPLT;
  case R_386_TLS_LDM:
    return R_TLSLD_GOTPLT;
  case R_386_PLT32:
    return R_PLT_PC;
  case R_386_PC8:
  case R_386_PC16:
  case R_386_PC32:
    return R_PC;
  case R_386_GOTPC:
    return R_GOTPLTONLY_PC;
  case R_386_TLS_IE:
    return R_GOT;
  case R_386_GOT32:
  case R_386_GOT32X:
    // These relocations are arguably mis-designed because their calculations
    // depend on the instructions they are applied to. This is bad because we
    // usually don't care about whether the target section contains valid
    // machine instructions or not. But this is part of the documented ABI, so
    // we had to implement as the standard requires.
    //
    // x86 does not support PC-relative data access. Therefore, in order to
    // access GOT contents, a GOT address needs to be known at link-time
    // (which means non-PIC) or compilers have to emit code to get a GOT
    // address at runtime (which means code is position-independent but
    // compilers need to emit extra code for each GOT access.) This decision
    // is made at compile-time. In the latter case, compilers emit code to
    // load a GOT address to a register, which is usually %ebx.
    //
    // So, there are two ways to refer to symbol foo's GOT entry: foo@GOT or
    // foo@GOT(%ebx).
    //
    // foo@GOT is not usable in PIC. If we are creating a PIC output and if we
    // find such relocation, we should report an error. foo@GOT is resolved to
    // an *absolute* address of foo's GOT entry, because both GOT address and
    // foo's offset are known. In other words, it's G + A.
    //
    // foo@GOT(%ebx) needs to be resolved to a *relative* offset from a GOT to
    // foo's GOT entry in the table, because GOT address is not known but foo's
    // offset in the table is known. It's G + A - GOT.
    //
    // It's unfortunate that compilers emit the same relocation for these
    // different use cases. In order to distinguish them, we have to read a
    // machine instruction.
    //
    // The following code implements it. We assume that Loc[0] is the first byte
    // of a displacement or an immediate field of a valid machine
    // instruction. That means a ModRM byte is at Loc[-1]. By taking a look at
    // the byte, we can determine whether the instruction uses the operand as an
    // absolute address (R_GOT) or a register-relative address (R_GOTPLT).
    return (loc[-1] & 0xc7) == 0x5 ? R_GOT : R_GOTPLT;
  case R_386_TLS_GOTIE:
    return R_GOTPLT;
  case R_386_GOTOFF:
    return R_GOTPLTREL;
  case R_386_TLS_LE:
    return R_TLS;
  case R_386_TLS_LE_32:
    return R_NEG_TLS;
  case R_386_NONE:
    return R_NONE;
  default:
    error(getErrorLocation(loc) + "unknown relocation (" + Twine(type) +
          ") against symbol " + toString(s));
    return R_NONE;
  }
}

RelExpr X86::adjustRelaxExpr(RelType type, const uint8_t *data,
                             RelExpr expr) const {
  switch (expr) {
  default:
    return expr;
  case R_RELAX_TLS_GD_TO_IE:
    return R_RELAX_TLS_GD_TO_IE_GOTPLT;
  case R_RELAX_TLS_GD_TO_LE:
    return R_RELAX_TLS_GD_TO_LE_NEG;
  }
}

void X86::writeGotPltHeader(uint8_t *buf) const {
  write32le(buf, mainPart->dynamic->getVA());
}

void X86::writeGotPlt(uint8_t *buf, const Symbol &s) const {
  // Entries in .got.plt initially points back to the corresponding
  // PLT entries with a fixed offset to skip the first instruction.
  write32le(buf, s.getPltVA() + 6);
}

void X86::writeIgotPlt(uint8_t *buf, const Symbol &s) const {
  // An x86 entry is the address of the ifunc resolver function.
  write32le(buf, s.getVA());
}

RelType X86::getDynRel(RelType type) const {
  if (type == R_386_TLS_LE)
    return R_386_TLS_TPOFF;
  if (type == R_386_TLS_LE_32)
    return R_386_TLS_TPOFF32;
  return type;
}

void X86::writePltHeader(uint8_t *buf) const {
  if (config->isPic) {
    const uint8_t v[] = {
        0xff, 0xb3, 0x04, 0x00, 0x00, 0x00, // pushl 4(%ebx)
        0xff, 0xa3, 0x08, 0x00, 0x00, 0x00, // jmp *8(%ebx)
        0x90, 0x90, 0x90, 0x90              // nop
    };
    memcpy(buf, v, sizeof(v));
    return;
  }

  const uint8_t pltData[] = {
      0xff, 0x35, 0, 0, 0, 0, // pushl (GOTPLT+4)
      0xff, 0x25, 0, 0, 0, 0, // jmp *(GOTPLT+8)
      0x90, 0x90, 0x90, 0x90, // nop
  };
  memcpy(buf, pltData, sizeof(pltData));
  uint32_t gotPlt = in.gotPlt->getVA();
  write32le(buf + 2, gotPlt + 4);
  write32le(buf + 8, gotPlt + 8);
}

void X86::writePlt(uint8_t *buf, const Symbol &sym,
                   uint64_t pltEntryAddr) const {
  unsigned relOff = in.relaPlt->entsize * sym.pltIndex;
  if (config->isPic) {
    const uint8_t inst[] = {
        0xff, 0xa3, 0, 0, 0, 0, // jmp *foo@GOT(%ebx)
        0x68, 0,    0, 0, 0,    // pushl $reloc_offset
        0xe9, 0,    0, 0, 0,    // jmp .PLT0@PC
    };
    memcpy(buf, inst, sizeof(inst));
    write32le(buf + 2, sym.getGotPltVA() - in.gotPlt->getVA());
  } else {
    const uint8_t inst[] = {
        0xff, 0x25, 0, 0, 0, 0, // jmp *foo@GOT
        0x68, 0,    0, 0, 0,    // pushl $reloc_offset
        0xe9, 0,    0, 0, 0,    // jmp .PLT0@PC
    };
    memcpy(buf, inst, sizeof(inst));
    write32le(buf + 2, sym.getGotPltVA());
  }

  write32le(buf + 7, relOff);
  write32le(buf + 12, in.plt->getVA() - pltEntryAddr - 16);
}

int64_t X86::getImplicitAddend(const uint8_t *buf, RelType type) const {
  switch (type) {
  case R_386_8:
  case R_386_PC8:
    return SignExtend64<8>(*buf);
  case R_386_16:
  case R_386_PC16:
    return SignExtend64<16>(read16le(buf));
  case R_386_32:
  case R_386_GOT32:
  case R_386_GOT32X:
  case R_386_GOTOFF:
  case R_386_GOTPC:
  case R_386_PC32:
  case R_386_PLT32:
  case R_386_TLS_LDO_32:
  case R_386_TLS_LE:
    return SignExtend64<32>(read32le(buf));
  default:
    return 0;
  }
}

void X86::relocate(uint8_t *loc, const Relocation &rel, uint64_t val) const {
  switch (rel.type) {
  case R_386_8:
    // R_386_{PC,}{8,16} are not part of the i386 psABI, but they are
    // being used for some 16-bit programs such as boot loaders, so
    // we want to support them.
    checkIntUInt(loc, val, 8, rel);
    *loc = val;
    break;
  case R_386_PC8:
    checkInt(loc, val, 8, rel);
    *loc = val;
    break;
  case R_386_16:
    checkIntUInt(loc, val, 16, rel);
    write16le(loc, val);
    break;
  case R_386_PC16:
    // R_386_PC16 is normally used with 16 bit code. In that situation
    // the PC is 16 bits, just like the addend. This means that it can
    // point from any 16 bit address to any other if the possibility
    // of wrapping is included.
    // The only restriction we have to check then is that the destination
    // address fits in 16 bits. That is impossible to do here. The problem is
    // that we are passed the final value, which already had the
    // current location subtracted from it.
    // We just check that Val fits in 17 bits. This misses some cases, but
    // should have no false positives.
    checkInt(loc, val, 17, rel);
    write16le(loc, val);
    break;
  case R_386_32:
  case R_386_GOT32:
  case R_386_GOT32X:
  case R_386_GOTOFF:
  case R_386_GOTPC:
  case R_386_PC32:
  case R_386_PLT32:
  case R_386_RELATIVE:
  case R_386_TLS_DTPMOD32:
  case R_386_TLS_DTPOFF32:
  case R_386_TLS_GD:
  case R_386_TLS_GOTIE:
  case R_386_TLS_IE:
  case R_386_TLS_LDM:
  case R_386_TLS_LDO_32:
  case R_386_TLS_LE:
  case R_386_TLS_LE_32:
  case R_386_TLS_TPOFF:
  case R_386_TLS_TPOFF32:
    checkInt(loc, val, 32, rel);
    write32le(loc, val);
    break;
  default:
    llvm_unreachable("unknown relocation");
  }
}

void X86::relaxTlsGdToLe(uint8_t *loc, const Relocation &, uint64_t val) const {
  // Convert
  //   leal x@tlsgd(, %ebx, 1),
  //   call __tls_get_addr@plt
  // to
  //   movl %gs:0,%eax
  //   subl $x@ntpoff,%eax
  const uint8_t inst[] = {
      0x65, 0xa1, 0x00, 0x00, 0x00, 0x00, // movl %gs:0, %eax
      0x81, 0xe8, 0, 0, 0, 0,             // subl Val(%ebx), %eax
  };
  memcpy(loc - 3, inst, sizeof(inst));
  write32le(loc + 5, val);
}

void X86::relaxTlsGdToIe(uint8_t *loc, const Relocation &, uint64_t val) const {
  // Convert
  //   leal x@tlsgd(, %ebx, 1),
  //   call __tls_get_addr@plt
  // to
  //   movl %gs:0, %eax
  //   addl x@gotntpoff(%ebx), %eax
  const uint8_t inst[] = {
      0x65, 0xa1, 0x00, 0x00, 0x00, 0x00, // movl %gs:0, %eax
      0x03, 0x83, 0, 0, 0, 0,             // addl Val(%ebx), %eax
  };
  memcpy(loc - 3, inst, sizeof(inst));
  write32le(loc + 5, val);
}

// In some conditions, relocations can be optimized to avoid using GOT.
// This function does that for Initial Exec to Local Exec case.
void X86::relaxTlsIeToLe(uint8_t *loc, const Relocation &rel,
                         uint64_t val) const {
  // Ulrich's document section 6.2 says that @gotntpoff can
  // be used with MOVL or ADDL instructions.
  // @indntpoff is similar to @gotntpoff, but for use in
  // position dependent code.
  uint8_t reg = (loc[-1] >> 3) & 7;

  if (rel.type == R_386_TLS_IE) {
    if (loc[-1] == 0xa1) {
      // "movl foo@indntpoff,%eax" -> "movl $foo,%eax"
      // This case is different from the generic case below because
      // this is a 5 byte instruction while below is 6 bytes.
      loc[-1] = 0xb8;
    } else if (loc[-2] == 0x8b) {
      // "movl foo@indntpoff,%reg" -> "movl $foo,%reg"
      loc[-2] = 0xc7;
      loc[-1] = 0xc0 | reg;
    } else {
      // "addl foo@indntpoff,%reg" -> "addl $foo,%reg"
      loc[-2] = 0x81;
      loc[-1] = 0xc0 | reg;
    }
  } else {
    assert(rel.type == R_386_TLS_GOTIE);
    if (loc[-2] == 0x8b) {
      // "movl foo@gottpoff(%rip),%reg" -> "movl $foo,%reg"
      loc[-2] = 0xc7;
      loc[-1] = 0xc0 | reg;
    } else {
      // "addl foo@gotntpoff(%rip),%reg" -> "leal foo(%reg),%reg"
      loc[-2] = 0x8d;
      loc[-1] = 0x80 | (reg << 3) | reg;
    }
  }
  write32le(loc, val);
}

void X86::relaxTlsLdToLe(uint8_t *loc, const Relocation &rel,
                         uint64_t val) const {
  if (rel.type == R_386_TLS_LDO_32) {
    write32le(loc, val);
    return;
  }

  // Convert
  //   leal foo(%reg),%eax
  //   call ___tls_get_addr
  // to
  //   movl %gs:0,%eax
  //   nop
  //   leal 0(%esi,1),%esi
  const uint8_t inst[] = {
      0x65, 0xa1, 0x00, 0x00, 0x00, 0x00, // movl %gs:0,%eax
      0x90,                               // nop
      0x8d, 0x74, 0x26, 0x00,             // leal 0(%esi,1),%esi
  };
  memcpy(loc - 2, inst, sizeof(inst));
}

TargetInfo *getX86TargetInfo() {
  static X86 t;
  return &t;
}

} // namespace elf
} // namespace lld
