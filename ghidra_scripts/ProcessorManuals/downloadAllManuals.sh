#!/bin/bash

# Git repo of this script: https://github.com/mwales/security/blob/master/ghidra_scripts/ProcessorManuals/downloadAllManuals.sh

downloadManual () {
	# Param 1 = URL of download
	# Param 2 = Destination
	
	# make the folder if it doesn't exist
	outputFolder=$(dirname $2)
	outputFile=$(basename $2)
	mkdir -p $outputFolder

	# if output already exists, don't re-download
	if [ -e $2 ];
	then
		echo "Already have $outputFile"
		return
	else
		echo "Downloading $outputFile from $1"
		wget $1 -O $2
	fi
}

# download the processor manuals

# 6502: no .idx file for manual

# 68000
downloadManual https://www.nxp.com/files-static/archives/doc/ref_manual/M68000PRM.pdf Ghidra/Processors/68000/data/manuals/M68000PRM.pdf

# 6805: no .idx file

# 8051
downloadManual https://www.keil.com/dd/docs/datashts/intel/8xc251sx_um.pdf Ghidra/Processors/8051/data/manuals/8xc251sx_um.pdf

# 8085: no .idx file

# AARCH64: no .idx file

# ARM
downloadManual https://www.cs.utexas.edu/~simon/378/resources/ARMv7-AR_TRM.pdf Ghidra/Processors/ARM/data/manuals/Armv7AR_errata.pdf 

# Atmel
# wrong .idx: downloadManual https://ww1.microchip.com/downloads/en/devicedoc/doc32000.pdf Ghidra/Processors/Atmel/data/manuals/doc32000.pdf

# CR16
downloadManual https://pubweb.eng.utah.edu/~cs3710/handouts/cr16.pdf Ghidra/Processors/CR16/data/manuals/cr16.pdf
#wget ... -O Ghidra/Processors/CR16/data/manuals/prog16c.pdf

# JVM
downloadManual https://docs.oracle.com/javase/specs/jvms/se8/jvms8.pdf Ghidra/Processors/JVM/data/manuals/jvms8.pdf

# MIPS
# .idx doesn't align: wget https://www.ece.lsu.edu/ee4720/mips64v2.pdf -O Ghidra/Processors/MIPS/data/manuals/mips64v2.pdf
#wget ... -O Ghidra/Processors/MIPS/data/manuals/MD00087-2B-MIPS64BIS-AFP-06.03.pdf
downloadManual https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00076-2B-MIPS1632-AFP-02.63.pdf Ghidra/Processors/MIPS/data/manuals/MD00076-2B-MIPS1632-AFP-02.63.pdf
# 404 not found: wget https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD00087-2B-MIPS64BIS-AFP-6.03.pdf -O Ghidra/Processors/MIPS/data/manuals/MD00087-2B-MIPS64BIS-AFP-06.03.pdf
downloadManual https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/MD000594-2B-microMIPS64-AFP-06.02.pdf Ghidra/Processors/MIPS/data/manuals/MD000594-2B-microMIPS64-AFP-06.02.pdf
# .idx doesn't align: wget https://github.com/f47h3r/firmware_reversing/raw/master/docs/research/MD00582-2B-microMIPS32-AFP-05.03.pdf -O Ghidra/Processors/MIPS/data/manuals/MD00582-2B0microMIPS32-AFP-05.03.pdf
downloadManual https://groups.csail.mit.edu/cag/raw/documents/R4400_Uman_book_Ed2.pdf Ghidra/Processors/MIPS/data/manuals/r4000.pdf


# PA-RISC
downloadManual http://ftp.parisc-linux.org/docs/arch/pa11_acd.pdf Ghidra/Processors/PA-RISC/data/manuals/pa11_acd.pdf

# PIC
downloadManual https://ww1.microchip.com/downloads/en/devicedoc/40139e.pdf Ghidra/Processors/PIC/data/manuals/PIC12_40139e.pdf
downloadManual https://ww1.microchip.com/downloads/en/DeviceDoc/40001761E.pdf Ghidra/Processors/PIC/data/manuals/PIC16F_40001761E.pdf
downloadManual https://ww1.microchip.com/downloads/en/devicedoc/33023a.pdf Ghidra/Processors/PIC/data/manuals/PIC16_33023a.pdf
downloadManual https://ww1.microchip.com/downloads/en/devicedoc/30289b.pdf Ghidra/Processors/PIC/data/manuals/PIC17_30289b.pdf
# .idx doesn't align: downloadManual https://www.farnell.com/datasheets/22241.pdf Ghidra/Processors/PIC/data/manuals/PIC18_14702.pdf
# .idx doesn't align: downloadManual https://ww1.microchip.com/downloads/en/DeviceDoc/70157D.pdf Ghidra/Processors/PIC/data/manuals/PIC24_70157D.pdf

# PowerPC
downloadManual http://kib.kiev.ua/x86docs/POWER/PowerISA_V2.06B_V2_PUBLIC.pdf Ghidra/Processors/PowerPC/data/manuals/PowerISA_V2.06_PUBLIC.pdf
downloadManual http://kib.kiev.ua/x86docs/POWER/PowerISA_V2.07B.pdf Ghidra/Processors/PowerPC/data/manuals/PowerISA_V2.07B.pdf
downloadManual http://kib.kiev.ua/x86docs/POWER/PowerISA_V3.0.pdf Ghidra/Processors/PowerPC/data/manuals/PowerISA_V3.0.pdf
downloadManual https://wiki.alcf.anl.gov/images/f/fb/PowerPC_-_Assembly_-_IBM_Programming_Environment_2.3.pdf Ghidra/Processors/PowerPC/data/manuals/powerpc.pdf
downloadManual http://dec8.info/Apple/macos8pdfs/CD_MacOS_8_9_X_4D_Omnis/Apple/MPC7450/ALTIVECPEM.pdf Ghidra/Processors/PowerPC/data/manuals/altivecpem.pdf

# Sparc
downloadManual https://cr.yp.to/2005-590/sparcv9.pdf Ghidra/Processors/Sparc/data/manuals/SPARCV9.pdf

# TI_MSP430
downloadManual https://e2echina.ti.com/cfs-file/__key/telligent-evolution-components-attachments/00-55-01-00-00-00-61-61/MSP430x2xx-Family-User_26002300_39_3B00_s-Guide-_2800_Rev.-E_2900_.pdf Ghidra/Processors/TI_MSP430/data/manuals/MSP430.pdf

# x86
downloadManual http://kib.kiev.ua/x86docs/SDMs/253666-029.pdf Ghidra/Processors/x86/data/manuals/Intel64_IA32_SoftwareDevelopersManual_vol2a.pdf
downloadManual http://kib.kiev.ua/x86docs/SDMs/253667-029.pdf Ghidra/Processors/x86/data/manuals/Intel64_IA32_SoftwareDevelopersManual_vol2b.pdf
# .idx doesn't align: wget https://www.amd.com/system/files/TechDocs/24594.pdf Ghidra/Processors/x86/data/manuals/AMD64_ProgrammersManual_vol3.pdf
# .idx doesn't align: wget https://www.amd.com/system/files/TechDocs/26568.pdf -O Ghidra/Processors/x86/data/manuals/AMD64_ProgrammersManual_vol4.pdf
# .idx doesn't align: wget https://www.amd.com/system/files/TechDocs/26569_APM_V5.pdf -O Ghidra/Processors/x86/data/manuals/AMD64_ProgrammersManual_vol5.pdf
# .idx doesn't align: wget https://www.amd.com/system/files/TechDocs/43479.pdf -O Ghidra/Processors/x86/data/manuals/AMD64_128-bit_SSE5_Instructions.pdf

# Z80
# .idx doesn't align: wget "https://www.zilog.com/force_download.php?filepath=YUhSMGNEb3ZMM2QzZHk1NmFXeHZaeTVqYjIwdlpHOWpjeTk2TVRnd0wzVnRNREExTUM1d1pHWT0=" -O Ghidra/Processors/Z80/data/manuals/um0050.pdf
downloadManual "https://www.zilog.com/force_download.php?filepath=YUhSMGNEb3ZMM2QzZHk1NmFXeHZaeTVqYjIwdlpHOWpjeTk2T0RBdlZVMHdNRGd3TG5Ca1pnPT0=" Ghidra/Processors/Z80/data/manuals/UM0080.pdf

