#!/bin/bash
# Reassembly script for il2cpp_game.exe
# Usage: bash reassemble.sh
cat il2cpp_game.exe.part_00 il2cpp_game.exe.part_01 il2cpp_game.exe.part_02 il2cpp_game.exe.part_03 il2cpp_game.exe.part_04 > il2cpp_game.exe
echo "Reassembled to il2cpp_game.exe"
echo "Expected size: 400801192 bytes"
wc -c il2cpp_game.exe
