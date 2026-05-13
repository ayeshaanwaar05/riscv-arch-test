# Ssstateen.py
#
# Ssstateen state-enable extension test generator.
# SPDX-License-Identifier: Apache-2.0
##################################

"""Ssstateen privileged extension test generator."""

from testgen.asm.csr import csr_walk_test, gen_csr_read_sigupd
from testgen.asm.helpers import comment_banner
from testgen.data.state import TestData
from testgen.priv.registry import add_priv_test_generator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enter_umode(test_data: TestData, temp_reg: int) -> list[str]:
    """Drop to U-mode via RVTEST macro."""
    return [
        "\tRVTEST_GOTO_LOWER_MODE Umode  # enter U-mode",
    ]


def _enter_smode(test_data: TestData, temp_reg: int) -> list[str]:
    """Drop to S-mode via RVTEST macro."""
    return [
        "\tRVTEST_GOTO_LOWER_MODE Smode  # enter S-mode",
    ]


def _return_mmode(test_data: TestData, temp_reg: int) -> list[str]:
    """Return to M-mode via RVTEST macro."""
    return [
        "\tRVTEST_GOTO_MMODE  # return to M-mode",
    ]


# ---------------------------------------------------------------------------
# cp_mstateen0_se0_controls_sstateen0
#   (cross csrrw, se0_state, sstateen_csrs — sstateen0 only per ignore_bins)
#   → CSRRW to sstateen0 from M-mode with mstateen0.SE0=0 and =1.
#   When SE0=0, writes to sstateen0 from lower modes should have no effect;
#   when SE0=1 they are permitted.  We test the write itself and capture
#   both mstateen0 and sstateen0 in the signature so the checker can verify.
# ---------------------------------------------------------------------------


def _generate_se0_controls_sstateen0(test_data: TestData) -> list[str]:
    coverpoint = "cp_mstateen0_se0_controls_sstateen0"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "CSRRW to sstateen0 with mstateen0.SE0 enabled and disabled",
        )
    )

    temp_reg, save_mstateen, save_sstateen, ones_reg = test_data.int_regs.get_registers(4, exclude_regs=[0])

    # SE0 is bit 63 on RV64 / bit 31 on RV32 of mstateen0
    lines.extend(
        [
            f"\tCSRR(x{save_mstateen}, mstateen0)   # save mstateen0",
            f"\tCSRR(x{save_sstateen}, sstateen0)   # save sstateen0",
            f"\tLI(x{ones_reg}, -1)",
        ]
    )

    for se0_state in [0, 1]:
        bit_action = "CSRC" if se0_state == 0 else "CSRS"
        lines.extend(
            [
                "",
                f"\t# mstateen0.SE0={se0_state}",
                # SE0 is the MSB — use all-ones/-zeros mask via CSRS/CSRC on bit 63/31
                "#ifdef XLEN64",
                f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                "#else",
                f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                "#endif",
                f"\t{bit_action}(mstateen0, x{temp_reg})  # set/clear SE0",
                "",
                test_data.add_testcase(f"csrrw_sstateen0_se0_{se0_state}", coverpoint, covergroup),
                f"\tCSRRW(x{temp_reg}, sstateen0, x{ones_reg})  # write all-ones to sstateen0",
                gen_csr_read_sigupd(temp_reg, "mstateen0", test_data),
                gen_csr_read_sigupd(temp_reg, "sstateen0", test_data),
            ]
        )

    lines.extend(
        [
            "",
            f"\tCSRW(mstateen0, x{save_mstateen})   # restore mstateen0",
            f"\tCSRW(sstateen0, x{save_sstateen})   # restore sstateen0",
        ]
    )

    test_data.int_regs.return_registers([temp_reg, save_mstateen, save_sstateen, ones_reg])
    return lines


# ---------------------------------------------------------------------------
# cp_csr_illegal_accesses  (cross priv_mode_u, csr, csrops, se0_state)
#   → From U-mode, attempt CSRRW/CSRRS/CSRRC/CSRR to each sstateenN CSR;
#   these should trap regardless of SE0.  We test with both SE0 states so
#   the cross bins are fully populated.
# ---------------------------------------------------------------------------


def _generate_csr_illegal_accesses(test_data: TestData) -> list[str]:
    coverpoint = "cp_csr_illegal_accesses"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "Attempt CSR ops to sstateenN CSRs from U-mode (should trap)",
        )
    )

    temp_reg, save_mstateen = test_data.int_regs.get_registers(2, exclude_regs=[0])

    sstateen_csrs = ["sstateen0", "sstateen1", "sstateen2", "sstateen3"]
    csr_ops = ["CSRRW", "CSRRS", "CSRRC", "CSRR"]

    for se0_state in [0, 1]:
        bit_action = "CSRC" if se0_state == 0 else "CSRS"
        lines.extend(
            [
                "",
                f"\t# se0_state={se0_state}",
                f"\tCSRR(x{save_mstateen}, mstateen0)",
                "#ifdef XLEN64",
                f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                "#else",
                f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                "#endif",
                f"\t{bit_action}(mstateen0, x{temp_reg})  # set/clear SE0",
            ]
        )
        lines.extend(_enter_umode(test_data, temp_reg))

        for csr in sstateen_csrs:
            for op in csr_ops:
                # CSRR takes only (rd, csr); CSRRW/CSRRS/CSRRC take (rd, csr, rs1)
                if op == "CSRR":
                    insn = f"\t{op}(x{temp_reg}, {csr})  # illegal from U-mode"
                else:
                    insn = f"\t{op}(x{temp_reg}, {csr}, x{temp_reg})  # illegal from U-mode"
                lines.extend(
                    [
                        "",
                        test_data.add_testcase(f"{csr}_{op.lower()}_umode_se0_{se0_state}", coverpoint, covergroup),
                        insn,
                        "\tnop",
                    ]
                )

        lines.extend(_return_mmode(test_data, temp_reg))
        lines.extend(
            [
                f"\tCSRW(mstateen0, x{save_mstateen})  # restore mstateen0",
            ]
        )

    test_data.int_regs.return_registers([temp_reg, save_mstateen])
    return lines


# ---------------------------------------------------------------------------
# cp_walking_ones  (cross csr, csrops, csr_walk, se0_state)
#   → Walking-1 and walking-0 patterns on sstateen0..3 with both SE0 states.
# ---------------------------------------------------------------------------


def _generate_walking_ones(test_data: TestData) -> list[str]:
    coverpoint = "cp_walking_ones"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "Walking-1 and walking-0 patterns written to each sstateenN CSR via CSRRW",
        )
    )

    save_reg, save_mstateen, temp_reg = test_data.int_regs.get_registers(3, exclude_regs=[0])

    sstateen_csrs = ["sstateen0", "sstateen1", "sstateen2", "sstateen3"]

    for se0_state in [0, 1]:
        bit_action = "CSRC" if se0_state == 0 else "CSRS"
        lines.extend(
            [
                "",
                f"\t# se0_state={se0_state}",
                f"\tCSRR(x{save_mstateen}, mstateen0)",
                "#ifdef XLEN64",
                f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                "#else",
                f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                "#endif",
                f"\t{bit_action}(mstateen0, x{temp_reg})  # set/clear SE0",
            ]
        )

        for csr in sstateen_csrs:
            lines.extend(
                [
                    "",
                    test_data.add_testcase(f"{csr}_walk_se0_{se0_state}", coverpoint, covergroup),
                    f"\tCSRR(x{save_reg}, {csr})   # save original value",
                ]
            )
            lines.extend(csr_walk_test(test_data, csr, covergroup, coverpoint))
            lines.extend(
                [
                    f"\tCSRW({csr}, x{save_reg})   # restore original value",
                ]
            )

        lines.extend(
            [
                "",
                f"\tCSRW(mstateen0, x{save_mstateen})  # restore mstateen0",
            ]
        )

    test_data.int_regs.return_registers([save_reg, save_mstateen, temp_reg])
    return lines


# ---------------------------------------------------------------------------
# cp_jvt  (cross csrrw, jvt_csr, jvt_state, se0_state)  [ifdef ZCMT_SUPPORTED]
#   → CSRRW to jvt with sstateen0.JVT bit=0 and =1, under both SE0 states.
#   jvt_state coverpoint reads sstateen0.jvt; se0_state reads mstateen0.SE0.
# ---------------------------------------------------------------------------


def _generate_jvt(test_data: TestData) -> list[str]:
    coverpoint = "cp_jvt"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "CSRRW to jvt CSR with sstateen0.JVT and mstateen0.SE0 enabled/disabled",
        )
    )

    temp_reg, save_mstateen, save_sstateen, save_jvt, ones_reg = test_data.int_regs.get_registers(5, exclude_regs=[0])

    # sstateen0 bit for JVT — bit 2 per the Ssstateen spec (mirrors Smstateen)
    JVT_BIT = 2

    lines.extend(
        [
            f"\tCSRR(x{save_mstateen}, mstateen0)   # save mstateen0",
            f"\tCSRR(x{save_sstateen}, sstateen0)   # save sstateen0",
            f"\tCSRR(x{save_jvt}, jvt)              # save jvt",
            f"\tLI(x{ones_reg}, -1)",
        ]
    )

    for se0_state in [0, 1]:
        se0_action = "CSRC" if se0_state == 0 else "CSRS"
        for jvt_state in [0, 1]:
            jvt_action = "CSRC" if jvt_state == 0 else "CSRS"
            lines.extend(
                [
                    "",
                    f"\t# mstateen0.SE0={se0_state}, sstateen0.JVT={jvt_state}",
                    "#ifdef XLEN64",
                    f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                    "#else",
                    f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                    "#endif",
                    f"\t{se0_action}(mstateen0, x{temp_reg})",
                    f"\tLI(x{temp_reg}, {1 << JVT_BIT})",
                    f"\t{jvt_action}(sstateen0, x{temp_reg})",
                    "",
                    test_data.add_testcase(f"csrrw_jvt_se0_{se0_state}_jvt_{jvt_state}", coverpoint, covergroup),
                    f"\tCSRRW(x{temp_reg}, jvt, x{ones_reg})  # write to jvt",
                    gen_csr_read_sigupd(temp_reg, "mstateen0", test_data),
                    gen_csr_read_sigupd(temp_reg, "sstateen0", test_data),
                    gen_csr_read_sigupd(temp_reg, "jvt", test_data),
                ]
            )

    lines.extend(
        [
            "",
            f"\tCSRW(mstateen0, x{save_mstateen})   # restore mstateen0",
            f"\tCSRW(sstateen0, x{save_sstateen})   # restore sstateen0",
            f"\tCSRW(jvt, x{save_jvt})              # restore jvt",
        ]
    )

    test_data.int_regs.return_registers([temp_reg, save_mstateen, save_sstateen, save_jvt, ones_reg])
    return lines


# ---------------------------------------------------------------------------
# cp_jvt_lower_mode  (cross priv_mode_u, csrops, jvt_csr, jvt_state, se0_state)
#   [ifdef ZCMT_SUPPORTED]
#   → From U-mode, CSRRW to jvt with all combinations of SE0 and JVT states.
# ---------------------------------------------------------------------------


def _generate_jvt_lower_mode(test_data: TestData) -> list[str]:
    coverpoint = "cp_jvt_lower_mode"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "CSRRW to jvt from U-mode with sstateen0.JVT and mstateen0.SE0 enabled/disabled",
        )
    )

    temp_reg, save_mstateen, save_sstateen, save_jvt = test_data.int_regs.get_registers(4, exclude_regs=[0])
    JVT_BIT = 2

    for se0_state in [0, 1]:
        se0_action = "CSRC" if se0_state == 0 else "CSRS"
        for jvt_state in [0, 1]:
            jvt_action = "CSRC" if jvt_state == 0 else "CSRS"
            lines.extend(
                [
                    "",
                    f"\t# mstateen0.SE0={se0_state}, sstateen0.JVT={jvt_state}",
                    f"\tCSRR(x{save_mstateen}, mstateen0)",
                    f"\tCSRR(x{save_sstateen}, sstateen0)",
                    f"\tCSRR(x{save_jvt}, jvt)",
                    "#ifdef XLEN64",
                    f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                    "#else",
                    f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                    "#endif",
                    f"\t{se0_action}(mstateen0, x{temp_reg})",
                    f"\tLI(x{temp_reg}, {1 << JVT_BIT})",
                    f"\t{jvt_action}(sstateen0, x{temp_reg})",
                ]
            )
            lines.extend(_enter_umode(test_data, temp_reg))
            lines.extend(
                [
                    "",
                    test_data.add_testcase(f"csrrw_jvt_se0_{se0_state}_jvt_{jvt_state}_umode", coverpoint, covergroup),
                    f"\tCSRRW(x{temp_reg}, jvt, x{temp_reg})  # write jvt from U-mode",
                    "\tnop",
                ]
            )
            lines.extend(_return_mmode(test_data, temp_reg))
            lines.extend(
                [
                    f"\tCSRW(mstateen0, x{save_mstateen})  # restore mstateen0",
                    f"\tCSRW(sstateen0, x{save_sstateen})  # restore sstateen0",
                    f"\tCSRW(jvt, x{save_jvt})             # restore jvt",
                ]
            )

    test_data.int_regs.return_registers([temp_reg, save_mstateen, save_sstateen, save_jvt])
    return lines


# ---------------------------------------------------------------------------
# cp_fcsr_lower
#   (cross priv_mode_s_u, misa_F, se0_state, sstateen0_fcsr_bit, csrops, fcsr_lower_mode_csrs)
#   [ifdef ZFINX_SUPPORTED]
#   → From S/U-mode, CSR ops on frm/fflags/fcsr under all combinations of
#   SE0 and sstateen0.FCSR states.
#   ignore_bins in the covergroup exclude the cases where sstateen0.FCSR=0 AND
#   misa_F is set or clear (those are covered separately); we still exercise
#   both states so the enabled bins are hit.
# ---------------------------------------------------------------------------


def _generate_fcsr_lower(test_data: TestData) -> list[str]:
    coverpoint = "cp_fcsr_lower"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "CSR ops on frm/fflags/fcsr from S/U-mode with sstateen0.FCSR and SE0 states",
        )
    )

    temp_reg, save_mstateen, save_sstateen, save_reg = test_data.int_regs.get_registers(4, exclude_regs=[0])
    fp_csrs = ["frm", "fflags", "fcsr"]

    # sstateen0 bit 0 = FCSR
    FCSR_BIT = 0

    for se0_state in [0, 1]:
        se0_action = "CSRC" if se0_state == 0 else "CSRS"
        for fcsr_bit in [0, 1]:
            fcsr_action = "CSRC" if fcsr_bit == 0 else "CSRS"
            for mode_label, enter_fn in [("smode", _enter_smode), ("umode", _enter_umode)]:
                lines.extend(
                    [
                        "",
                        f"\t# se0_state={se0_state}, sstateen0.FCSR={fcsr_bit}, {mode_label}",
                        f"\tCSRR(x{save_mstateen}, mstateen0)",
                        f"\tCSRR(x{save_sstateen}, sstateen0)",
                        "#ifdef XLEN64",
                        f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                        "#else",
                        f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                        "#endif",
                        f"\t{se0_action}(mstateen0, x{temp_reg})",
                        f"\tLI(x{temp_reg}, {1 << FCSR_BIT})",
                        f"\t{fcsr_action}(sstateen0, x{temp_reg})  # sstateen0.FCSR = {fcsr_bit}",
                    ]
                )
                lines.extend(enter_fn(test_data, temp_reg))
                for csr in fp_csrs:
                    lines.extend(
                        [
                            "",
                            test_data.add_testcase(
                                f"csrrw_{csr}_se0_{se0_state}_fcsr{fcsr_bit}_{mode_label}",
                                coverpoint,
                                covergroup,
                            ),
                            f"\tCSRR(x{save_reg}, {csr})",
                            f"\tCSRRW(x{temp_reg}, {csr}, x{save_reg})  # csrrw {csr} from {mode_label}",
                            "\tnop",
                        ]
                    )
                lines.extend(_return_mmode(test_data, temp_reg))
                lines.extend(
                    [
                        f"\tCSRW(mstateen0, x{save_mstateen})  # restore mstateen0",
                        f"\tCSRW(sstateen0, x{save_sstateen})  # restore sstateen0",
                    ]
                )

    test_data.int_regs.return_registers([temp_reg, save_mstateen, save_sstateen, save_reg])
    return lines


# ---------------------------------------------------------------------------
# cp_fcsr_lower_fp_instrs
#   (cross priv_mode_u, misa_F, se0_state, sstateen0_fcsr_bit, fp_instrs)
#   [ifdef ZFINX_SUPPORTED]
#   → From U-mode, execute each FP instruction under all combinations of
#   SE0 and sstateen0.FCSR.
# ---------------------------------------------------------------------------


def _generate_fcsr_lower_fp_instrs(test_data: TestData) -> list[str]:
    coverpoint = "cp_fcsr_lower_fp_instrs"
    covergroup = "Ssstateen_cg"

    lines = []
    lines.append(
        comment_banner(
            coverpoint,
            "FP instructions from U-mode with sstateen0.FCSR and SE0 states",
        )
    )

    temp_reg, save_mstateen, save_sstateen, scratch_reg = test_data.int_regs.get_registers(4, exclude_regs=[0])

    FCSR_BIT = 0

    fp_instrs = [
        "fadd.s f0, f1, f2",
        "flw f0, 0(x{scratch})",
        "fcvt.w.s x{temp}, f0",
        "fcvt.s.w f0, x0",
        "fmv.x.w x{temp}, f0",
        "fmv.w.x f0, x{temp}",
        "fclass.s x{temp}, f0",
    ]

    lines.extend(
        [
            f"\tLA(x{scratch_reg}, scratch)  # scratch memory pointer",
        ]
    )

    for se0_state in [0, 1]:
        se0_action = "CSRC" if se0_state == 0 else "CSRS"
        for fcsr_bit in [0, 1]:
            fcsr_action = "CSRC" if fcsr_bit == 0 else "CSRS"
            lines.extend(
                [
                    "",
                    f"\t# se0_state={se0_state}, sstateen0.FCSR={fcsr_bit}, umode",
                    f"\tCSRR(x{save_mstateen}, mstateen0)",
                    f"\tCSRR(x{save_sstateen}, sstateen0)",
                    "#ifdef XLEN64",
                    f"\tLI(x{temp_reg}, 0x8000000000000000)  # SE0 = bit 63",
                    "#else",
                    f"\tLI(x{temp_reg}, 0x80000000)          # SE0 = bit 31",
                    "#endif",
                    f"\t{se0_action}(mstateen0, x{temp_reg})",
                    f"\tLI(x{temp_reg}, {1 << FCSR_BIT})",
                    f"\t{fcsr_action}(sstateen0, x{temp_reg})  # sstateen0.FCSR = {fcsr_bit}",
                ]
            )
            lines.extend(_enter_umode(test_data, temp_reg))
            for insn_template in fp_instrs:
                insn = insn_template.replace("{temp}", str(temp_reg)).replace("{scratch}", str(scratch_reg))
                lines.extend(
                    [
                        "",
                        test_data.add_testcase(
                            f"{insn_template.split()[0]}_se0_{se0_state}_fcsr{fcsr_bit}_umode",
                            coverpoint,
                            covergroup,
                        ),
                        f"\t{insn}  # fp instr from umode se0={se0_state} fcsr={fcsr_bit}",
                        "\tnop",
                    ]
                )
            lines.extend(_return_mmode(test_data, temp_reg))
            lines.extend(
                [
                    f"\tCSRW(mstateen0, x{save_mstateen})  # restore mstateen0",
                    f"\tCSRW(sstateen0, x{save_sstateen})  # restore sstateen0",
                ]
            )

    test_data.int_regs.return_registers([temp_reg, save_mstateen, save_sstateen, scratch_reg])
    return lines


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


@add_priv_test_generator(
    "Ssstateen",
    required_extensions=["Ss", "Zicsr", "Ssstateen"],
    march_extensions=["Ssstateen", "Smstateen", "Zicsr", "Zcmt"],
)
def make_ssstateen(test_data: TestData) -> list[str]:
    """Generate tests for Ssstateen state-enable extension testsuite."""
    lines: list[str] = []

    # Unconditional coverpoints — required by all Ssstateen targets
    lines.extend(_generate_se0_controls_sstateen0(test_data))
    lines.extend(_generate_csr_illegal_accesses(test_data))
    lines.extend(_generate_walking_ones(test_data))

    # cp_fcsr_lower, cp_fcsr_lower_fp_instrs
    # Only when F (Zfinx) is supported — sstateen0.FCSR bit is relevant
    lines.append("#ifdef ZFINX_SUPPORTED")
    lines.extend(_generate_fcsr_lower(test_data))
    lines.extend(_generate_fcsr_lower_fp_instrs(test_data))
    lines.append("#endif  // ZFINX_SUPPORTED")

    # cp_jvt, cp_jvt_lower_mode
    # Only when Zcmt is supported — sstateen0.JVT bit is relevant
    lines.append("#ifdef ZCMT_SUPPORTED")
    lines.extend(_generate_jvt(test_data))
    lines.extend(_generate_jvt_lower_mode(test_data))
    lines.append("#endif  // ZCMT_SUPPORTED")

    return lines
