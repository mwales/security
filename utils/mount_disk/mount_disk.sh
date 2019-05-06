#!/bin/bash

UNMOUNT_SCRIPT=unmount_disk.sh

echo "#!/bin/bash" > $UNMOUNT_SCRIPT

if [ $# -ne 1 ];
then
	echo "Usage: mount_disk.sh diskFileName"
	echo "Will mount all the partitions found on the disk into seperate directories"
	echo "Will also create an unmount script to unmount them all and undo the previous script"
	exit 0
fi

# This command will output "add map loopName blah blah blah
# the loopName above doesn't include /dev/mapper path
partMappingText=$(sudo kpartx -asv $1)
echo -e "Output from kpartx:\n${partMappingText}"

justMapDrives=$(echo "$partMappingText" | cut -d' ' -f3)

for singleMap in $justMapDrives
do
	echo "Mounting $singleMap"

	mkdir $singleMap
	sudo mount /dev/mapper/$singleMap $singleMap

	echo -e "\n# Next Drive" >> $UNMOUNT_SCRIPT
	echo "sudo umount $singleMap" >> $UNMOUNT_SCRIPT
	echo "rmdir $singleMap" >> $UNMOUNT_SCRIPT
done






echo "#Remove all the loop devices created" >> $UNMOUNT_SCRIPT
echo "sudo kpartx -dv $1" >> $UNMOUNT_SCRIPT

chmod a+x $UNMOUNT_SCRIPT

