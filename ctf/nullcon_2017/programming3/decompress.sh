#!/bin/bash

FILE_OUTPUT=$(file $1)
echo "File program output: $FILE_OUTPUT"

LZMA=$(echo $FILE_OUTPUT | grep -o LZMA)
if [ "$LZMA" = "LZMA" ]; then
	echo "Handle LZMA"
	./lzma_decompress.py $1 temp_file
	cp temp_file $1
	echo "Done"
	exit 0
fi

TAR=$(echo $FILE_OUTPUT | grep -o tar)
if [ "$TAR" = "tar" ]; then
	echo "Handle tar"
	tar -xvf $1 > temp_file
	mv $(cat temp_file) $1
	exit 0
fi

XZ=$(echo $FILE_OUTPUT | grep -o XZ)
if [ "$XZ" = "XZ" ];then
	echo "Handle XZ"
	xzcat $1 > temp_file
	mv temp_file $1
	echo "Done"
	exit 0
fi

GZIP=$(echo $FILE_OUTPUT | grep -o gzip)
if [ "$GZIP" = "gzip" ]; then
	echo "Handle gzip"
	zcat $1 > temp_file
	mv temp_file $1
	echo "Done"
	exit 0
fi

BZIP2=$(echo $FILE_OUTPUT | grep -o bzip2)
if [ "$BZIP2" = "bzip2" ]; then
	echo "Handle bzip2"
	bzcat $1 > temp_file
	mv temp_file $1
	echo "Done"
	exit 0
fi

NUFILE=$(echo $FILE_OUTPUT | grep -o NuFile)
if [ "$NUFILE" = "NuFile" ]; then
	echo "Handle NuFx"
	cp $1 FartNuFile
	OUTPUT_FILE=$(./nulib2 -t FartNuFile)
	./nulib2 -x FartNuFile
	mv $OUTPUT_FILE $1
	echo "Done"
	exit 0
fi

LZIP=$(echo $FILE_OUTPUT | grep -o lzip)
if [ "$LZIP" = "lzip" ];then
	echo "Handle lzip"
	./lzip -d -c $1 > temp_file
	mv temp_file $1
	echo "Done"
	exit 0
fi

# ZPAQ
ZPAQ=$(echo $FILE_OUTPUT | grep -o ZPAQ)
if [ "$ZPAQ" = "ZPAQ" ];then
        echo "Handle ZPAQ"
	mkdir temp_dir
	cd temp_dir
	zpaq x ../$1
	mv * ../$1
	cd ..
	rm -rf temp_dir
        echo "Done"
        exit 0
fi

ZOO=$(echo $FILE_OUTPUT | grep -o Zoo)
if [ "$ZOO" = "Zoo" ]; then
	echo "Handle Zoo archive"
	mkdir zoo_temp
	cd zoo_temp
	cp ../$1 $1.zoo
	zoo x $1.zoo
	rm $1.zoo
	mv * ../$1
	cd ..
	rmdir zoo_temp
	echo "Done"
	exit 0
fi

SEVENZIP=$(echo $FILE_OUTPUT | grep -o 7-zip)
if [ "$SEVENZIP" = "7-zip" ]; then
	echo "Handle 7zip"
	mkdir 7ztemp
	cd 7ztemp
	7z x ../$1
	mv * ../$1
	cd ..
	rmdir 7ztemp
	echo "Done"
	exit 0
fi

ARJ=$(echo $FILE_OUTPUT | grep -o ARJ)
if [ "$ARJ" = "ARJ" ]; then
	echo "Handle ARJ"
	mkdir arjtemp
	cd arjtemp
	cp ../$1 $1.arj
	arj x $1.arj
	rm $1.arj
	mv * ../$1
	cd ..
	rmdir arjtemp
	echo "Done"
	exit 0
fi

ZIP=$(echo $FILE_OUTPUT | grep -o Zip)
if [ "$ZIP" = "Zip" ]; then
	echo "Handle Zip"
	mkdir ziptemp
	cd ziptemp
	cp ../$1 fart
	unzip fart
	rm fart
	mv * ../$1
	cd ..
	rmdir ziptemp
	echo "Done"
	exit 0
fi

echo "Unknown file type!"
exit 1


