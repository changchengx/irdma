#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

# usage:
# sudo su
# bash -x build_vf.sh eth2
# OR
# bash -x build_vf.sh eth2 2

function usage()
{
	echo "$ sudo su"
	echo "# bash -x build_vf.sh eth2"
	echo "## OR"
	echo "#bash -x build_vf.sh eth2 2"
}

declare PF_PCI

function get_pci_id()
{
    PF_PCI=`ls -l /sys/class/net/$1/device | awk '{print $NF}' | rev | cut -d '/' -f 1 | rev`
}

function get_port_id()
{
    PORT=${PF_PCI#*.}
}

IFACE=$1
if [ -z "IFACE" ]; then
	usage
	exit 1
fi

if [ ! -d /sys/class/net/$IFACE/device ]; then
	usage
	exit 1
fi

NUM_OF_VF=$2
if [ -z "$NUM_OF_VF" ] ; then
    NUM_OF_VF=2
fi

get_pci_id $IFACE
get_port_id

declare p=${PF_PCI%:00.*}
for ((idx=0; idx<NUM_OF_VF;idx++)) ; do
    df=$[idx+2+PORT*NUM_OF_VF]
    d=$[df/8]
    f=$[df%8]
    x=$(printf "$x $p:%02x.%d" $d $f)
done

declare -a VF=($x)
 
function unbind_vf()
{
    P=/sys/bus/pci/drivers/mlx5_core
    for vf in ${VF[@]} ; do
        ls -l $P/$vf
        if [ -e "$P/$vf" ] ; then
            echo $vf > $P/unbind
        fi
    done
    sleep 10
}
 
function recreate_vf()
{
  echo delete the VFs
  echo 0 > /sys/bus/pci/devices/$PF_PCI/sriov_numvfs
  sleep 10
  echo create the VFs
  echo $NUM_OF_VF > /sys/bus/pci/devices/$PF_PCI/sriov_numvfs
  sleep 20 
}
 
function set_switchdev_mode()
{
  echo set switchdev mode
  devlink dev eswitch set pci/$PF_PCI mode switchdev
}
 
function build_vf()
{
    unbind_vf
    recreate_vf
    unbind_vf
    set_switchdev_mode
}

build_vf
