import struct
from enum import Enum
from typing import NamedTuple

INPUT_CELL = 2**11 - 2 # TODO хуйня
OUTPUT_CELL = 2**11 - 1


class Opcode(Enum):
    LD: int = 0
    ST = 1
    ADD = 2
    SUB = 3
    DIV = 4
    MUL = 5
    MOD = 6
    CMP = 7
    JMP = 8
    BEQ = 9
    BNE = 10
    BL = 11
    BG = 12
    HLT = 13
    IN = 14
    OUT = 15


class AddrMode(Enum):
    DIRECT: int = 0
    INDIRECT = 1
    IMMEDIATE = 2


class Instruction(NamedTuple):
    opcode: Opcode
    addr_mode: AddrMode
    arg: int

    def __repr__(self):
        if (
            self.opcode == Opcode.HLT 
            or self.opcode == Opcode.IN
            or self.opcode == Opcode.OUT
        ):
            return self.opcode.name
        if (
            self.opcode == Opcode.JMP
            or self.opcode == Opcode.BEQ
            or self.opcode == Opcode.BNE
            or self.opcode == Opcode.BL
            or self.opcode == Opcode.BG
        ):
            return f"{self.opcode.name} {self.arg}"
        return f"{self.opcode.name} {['', '~', '#'][self.addr_mode.value]}{self.arg}"


# B - unsigned char; > - big-endian; I - unsigned int; i - signed int
def binary2code(filename) -> list:
    machine_code = []
    with open(filename, "rb") as file:
        while bin_code_instr := file.read(1):
            assert len(bin_code_instr) == 1, "Бинарный файл невалиден"

            op_and_mode = struct.unpack(">B", bin_code_instr)

            op = op_and_mode[0] >> 2

            if op == Opcode.HLT.value:
                machine_code.append(Instruction(Opcode(op), None, None))
                break
            mode = op_and_mode[0] & 0b11
            arg = file.read(4)  
            assert len(arg) == 4, "Бинарный файл невалиден"

            if AddrMode(mode) == AddrMode.DIRECT:
                arg = struct.unpack(">I", arg)
            else:
                arg = struct.unpack(">i", arg)
            machine_code.append(Instruction(Opcode(op), AddrMode(mode), arg[0]))

    return machine_code