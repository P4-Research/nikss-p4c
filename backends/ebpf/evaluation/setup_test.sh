#!/bin/bash

function print_help() {
  echo -e "Usage: "
  echo -e "\t $0 INTF_LIST P4_PROGRAM"
  echo -e "\t $0 --help"
  echo -e "Example: "
  echo -e "\t $0 ens1f0,ens1f1 testdata/l2fwd.p4"
  echo -e "\nWill configure eBPF environment, compile P4 program, run and report CPU profiling and usage statistics."
}

if [ "x$1" = "x--help" ]; then
  print_help
  exit 0
fi

function exit_on_error() {
      exit_code=$?
      if [ $exit_code -ne 0 ]; then
          exit $exit_code
      fi
}


function cleanup() {
    ip link del psa_recirc
    for intf in ${INTERFACES//,/ } ; do
        ip link set dev "$intf" xdp off
        tc qdisc del dev "$intf" clsact
    done
    make -f ../runtime/kernel.mk BPFOBJ=out.o clean
    psabpf-ctl pipeline unload id 99
    rm -rf /sys/fs/bpf/*
}

if (( $# != 2 )); then
    >&2 echo -e "Illegal number of arguments! \n"
    print_help
    exit 1
fi

declare -a INTERFACES=$1

cleanup 
#trap cleanup EXIT

ip link add name psa_recirc type dummy
ip link set dev psa_recirc up
echo "PSA_PORT_RECIRCULATE configuration:"
ip link show psa_recirc

declare -a RECIRC_PORT_ID=$(ip -o link | awk '$2 == "psa_recirc:" {print $1}' | awk -F':' '{print $1}')

# Trace all command from this point
#set -x

echo "Compiling data plane program.."
declare -a P4PROGRAM=$(find "$2" -maxdepth 1 -type f -name "*.p4")
declare -a ARGS="-DBTF -DPSA_PORT_RECIRCULATE=$RECIRC_PORT_ID"

if [ -n "$P4PROGRAM" ]; then
  echo "Found P4 program: $P4PROGRAM"
  make -f ../runtime/kernel.mk BPFOBJ=out.o \
      P4FILE=$P4PROGRAM ARGS="$ARGS" P4ARGS="$P4ARGS" psa
#<<<<<<< HEAD
  exit_on_error
  psabpf-ctl pipeline load id 99 out.o
#=======
#>>>>>>> efeb94fc81aebe380a110af48a3516a30e22bb15
  exit_on_error
else
  declare -a CFILE=$(find "$2" -maxdepth 1 -type f -name "*.c")
  if [ -z "$CFILE" ]; then
    echo "Neither P4 nor C file found under path $2"
    exit 1
  fi
  echo "Found C file: $CFILE"
  make -f ../runtime/kernel.mk BPFOBJ=out.o ARGS="$ARGS" ebpf CFILE=$CFILE
  bpftool prog loadall out.o /sys/fs/bpf/prog
  exit_on_error
fi

for intf in ${INTERFACES//,/ } ; do
  # Disable trash traffic
  sysctl -w net.ipv6.conf."$intf".disable_ipv6=1
  sysctl -w net.ipv6.conf."$intf".autoconf=0
  sysctl -w net.ipv6.conf."$intf".accept_ra=0
  
  ifconfig "$intf" promisc
#<<<<<<< HEAD
  ethtool -L "$intf" combined 1
  ethtool -G "$intf" tx 4096
  ethtool -G "$intf" rx 4096
  ethtool -K "$intf" txvlan off
  ethtool -K "$intf" rxvlan off

  # TODO: these commands are used if an eBPF program written in C is being tested.
  #  We should refactor this script.
  #bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev "$intf" overwrite
  #tc qdisc add dev "$intf" clsact
  #tc filter add dev "$intf" ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
  #tc filter add dev "$intf" egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress

  psabpf-ctl pipeline add-port id 99 "$intf"
#=======

  # TODO: move this to psabpf-ctl
  bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_ingress_xdp-ingress dev "$intf" #overwrite
  tc qdisc add dev "$intf" clsact
  tc filter add dev "$intf" ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
  tc filter add dev "$intf" egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress
#>>>>>>> efeb94fc81aebe380a110af48a3516a30e22bb15

  # by default, pin IRQ to 3rd CPU core
  bash scripts/set_irq_affinity.sh 2 "$intf"
done

echo "Installing table entries.. Looking for $2/commands.txt"
if [ -n "$2/commands.txt" ]; then
   cat $2/commands.txt
   bash $2/commands.txt
   echo "Table entries successfully installed!"
else
   echo "File with table entries not provided"
fi

echo -e "Dumping network configuration:"
# dump network configuration
for intf in ${INTERFACES//,/ } ; do
  ip link show "$intf"
done

echo -e "Populating crc lookup table"

__generate_crc_lookup_table_standard() {

  local -i -r LSB_CRC32_POLY=0xEDB88320 # The CRC32 polynomal LSB order
    local -i index, index2 byte lsb, lkp1a, lkp1b,lkp1c, lkp2a, lkp2b,lkp2c, lkp3a, lkp3b,lkp3c,ins,ins2,ins3

      for index in {0..255}; do
        #((byte = 255 - index))
        #for _ in {0..7}; do # 8-bit lsb shift
        #  ((lsb = byte & 0x01, byte = ((byte >> 1) & 0x7FFFFFFF) ^ (lsb == 0 ? LSB_CRC32_POLY : 0)))
        #done
        byte=index
        for _ in {0..7}; do # 8-bit lsb shift

            byte=$(((byte>>1) ^ ((byte & 1)*LSB_CRC32_POLY)))

        done
        calc=$(printf "%08x" $byte)
        BECALC="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
        #printf "%0x" $byte
        #echo "BE crc $BECALC"
        #echo "ins=$calc"

        bpftool map update name crc_lookup_tbl key hex $(printf "%x" $index) 00 00 00  value  hex $BECALC
      done
    }

__generate_crc_lookup_table() {

  local -i -r LSB_CRC32_POLY=0xEDB88320 # The CRC32 polynomal LSB order
  local -i index, index2 byte lsb, lkp1a, lkp1b,lkp1c, lkp2a, lkp2b,lkp2c, lkp3a, lkp3b,lkp3c,ins,ins2,ins3

    for index in {0..255}; do
      #((byte = 255 - index))
      #for _ in {0..7}; do # 8-bit lsb shift
      #  ((lsb = byte & 0x01, byte = ((byte >> 1) & 0x7FFFFFFF) ^ (lsb == 0 ? LSB_CRC32_POLY : 0)))
      #done
      byte=index
      for _ in {0..7}; do # 8-bit lsb shift

          byte=$(((byte>>1) ^ ((byte & 1)*LSB_CRC32_POLY)))

      done
      calc=$(printf "%08x" $byte)
      BECALC="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
      #printf "%0x" $byte
      #echo "BE crc $BECALC"
      #echo "ins=$calc"

      bpftool map update name crc_lookup_tbl1 key hex $(printf "%x" $index) 00 00 00  value  hex $BECALC
    done

    for index2 in {0..255}; do

      lkp1a=$( bpftool map lookup name crc_lookup_tbl1 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
      ((lkp1b=lkp1a & 0xFF))
      calc=$(printf "%08x" $lkp1b)
      #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
      lkp1c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
      ((ins=(lkp1a >> 8) ^ lkp1c))
      #printf "lkp1b = %0x\n" $lkp1b
      #echo "index2= $(printf "%x" $index2)"
      calc2=$(printf "%08x" $ins)
      BECALC2="${calc2:6:2} ${calc2:4:2} ${calc2:2:2} ${calc2:0:2}"
      #printf "%0x" $calc2
      #echo "ins=$calc2"
      bpftool map update name crc_lookup_tbl2 key hex $(printf "%x" $index2) 00 00 00  value  hex $BECALC2

      lkp2a=$( bpftool map lookup name crc_lookup_tbl2 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
            ((lkp2b=lkp2a & 0xFF))
            calc=$(printf "%08x" $lkp2b)
            BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
            lkp2c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
            ((ins2=(lkp2a >> 8) ^ lkp2c))
            #printf "lkp1b = %0x\n" $lkp1b
            #echo "index2= $(printf "%x" $index2)"
            calc3=$(printf "%08x" $ins2)
            BECALC3="${calc3:6:2} ${calc3:4:2} ${calc3:2:2} ${calc3:0:2}"
            #printf "%0x" $calc2
            #echo "ins3=$calc3"
            bpftool map update name crc_lookup_tbl3 key hex $(printf "%x" $index2) 00 00 00  value  hex $BECALC3

      lkp3a=$( bpftool map lookup name crc_lookup_tbl3 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
                  ((lkp3b=lkp3a & 0xFF))
                  calc=$(printf "%08x" $lkp3b)
                  BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
                  lkp3c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
                  ((ins3=(lkp3a >> 8) ^ lkp3c))
                  #printf "lkp1b = %0x\n" $lkp1b
                  #echo "index2= $(printf "%x" $index2)"
                  calc4=$(printf "%08x" $ins3)
                  BECALC4="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2}"
                  #printf "%0x" $calc2
                  echo " $index2 : bpftool map update name crc_lookup_tbl4 key hex $(printf "%x" $index2) 00 00 00  value  hex $BECALC4"
                  bpftool map update name crc_lookup_tbl4 key hex $(printf "%x" $index2) 00 00 00  value  hex $BECALC4


    done

}

__generate_crc_lookup_table2() {
    local -i -r LSB_CRC32_POLY=0xEDB88320 # The CRC32 polynomal LSB order
    local -i index, index2 byte lsb, lkp1a, lkp1b,lkp1c, lkp2a, lkp2b,lkp2c, lkp3a, lkp3b,lkp3c,ins,ins2,ins3
    TABLE=""
      for index in {0..255}; do
        byte=index
              for _ in {0..7}; do # 8-bit lsb shift

                  byte=$(((byte>>1) ^ ((byte & 1)*LSB_CRC32_POLY)))

              done
        calc=$(printf "%08x" $byte)
        TABLE+="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2} "
        #printf "%0x" $byte
        #echo "BE crc $BECALC"
      done
      bpftool map update name crc_lookup_tbl key hex  00 00 00 00  value  hex $TABLE
    echo "$TABLE"
}
__generate_crc_lookup_table3() {

  local -i -r LSB_CRC32_POLY=0xEDB88320 # The CRC32 polynomal LSB order
  local -i index, index2 byte lsb, lkp1a, lkp1b,lkp1c, lkp2a, lkp2b,lkp2c, lkp3a, lkp3b,lkp3c,ins,ins2,ins3
  TABLE=""
  TABLE2=""
  TABLE3=""
  TABLE4=""
  declare -a calc_tbl
  declare -a calc_tbl2
  declare -a calc_tbl3
  declare -a calc_tbl4
    for index in {0..255}; do

      byte=index
      for _ in {0..7}; do # 8-bit lsb shift

          byte=$(((byte>>1) ^ ((byte & 1)*LSB_CRC32_POLY)))

      done
      calc_tbl[index]=$byte
      calc=$(printf "%08x" $byte)

      #printf "%0x" $byte
      #echo "BE crc $BECALC"
      #echo "ins=$calc"
      TABLE+="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2} "

    done

    for index2 in {0..255}; do

      lkp1a=$( bpftool map lookup name crc_lookup_tbl1 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp1a=${calc_tbl[$index2]}
      ((lkp1b=lkp1a & 0xFF))
      calc=$(printf "%08x" $lkp1b)
      #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
      #lkp1c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp1c=${calc_tbl[$lkp1b]}
      ((ins=(lkp1a >> 8) ^ lkp1c))
      #printf "lkp1b = %0x\n" $lkp1b
      #echo "index2= $(printf "%x" $index2)"
      calc_tbl2[index2]=$ins
      calc2=$(printf "%08x" $ins)
      TABLE2+="${calc2:6:2} ${calc2:4:2} ${calc2:2:2} ${calc2:0:2} "

      #lkp2a=$( bpftool map lookup name crc_lookup_tbl2 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp2a=${calc_tbl2[$index2]}
            ((lkp2b=lkp2a & 0xFF))
            #calc=$(printf "%08x" $lkp2b)
            #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
            #lkp2c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
            lkp2c=${calc_tbl[$lkp2b]}
            ((ins2=(lkp2a >> 8) ^ lkp2c))
            #printf "lkp1b = %0x\n" $lkp1b
            #echo "index2= $(printf "%x" $index2)"
            calc_tbl3[index2]=$ins2
            calc3=$(printf "%08x" $ins2)
            TABLE3+="${calc3:6:2} ${calc3:4:2} ${calc3:2:2} ${calc3:0:2} "
      #lkp3a=$( bpftool map lookup name crc_lookup_tbl3 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
                  lkp3a=${calc_tbl3[$index2]}
                  ((lkp3b=lkp3a & 0xFF))
                  #calc=$(printf "%08x" $lkp3b)
                  #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
                  #lkp3c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
                  lkp3c=${calc_tbl[$lkp3b]}
                  ((ins3=(lkp3a >> 8) ^ lkp3c))
                  #printf "lkp1b = %0x\n" $lkp1b
                  #echo "index2= $(printf "%x" $index2)"
                  calc_tbl4[index2]=$ins3
                  calc4=$(printf "%08x" $ins3)
                  TABLE4+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "



    done
    TABLE+=$TABLE2
    TABLE+=$TABLE3
    TABLE+=$TABLE4
    echo $TABLE
    bpftool map update name crc_lookup_tbl key hex  00 00 00 00  value  hex $TABLE
}


__generate_crc_lookup_table4() {

  local -i -r LSB_CRC32_POLY=0xEDB88320 # The CRC32 polynomal LSB order
  local -i index, index2 byte lsb, lkp1a, lkp1b,lkp1c, lkp2a, lkp2b,lkp2c, lkp3a, lkp3b,lkp3c,ins,ins2,ins3
  TABLE=""
  TABLE2=""
  TABLE3=""
  TABLE4=""
  TABLE5=""
  TABLE6=""
  TABLE7=""
  TABLE8=""
  declare -a calc_tbl
  declare -a calc_tbl2
  declare -a calc_tbl3
  declare -a calc_tbl4
  declare -a calc_tbl5
  declare -a calc_tbl6
  declare -a calc_tbl7
  declare -a calc_tbl8
    for index in {0..255}; do

      byte=index
      for _ in {0..7}; do # 8-bit lsb shift

          byte=$(((byte>>1) ^ ((byte & 1)*LSB_CRC32_POLY)))

      done
      calc_tbl[index]=$byte
      calc=$(printf "%08x" $byte)

      #printf "%0x" $byte
      #echo "BE crc $BECALC"
      #echo "ins=$calc"
      TABLE+="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2} "

    done

    for index2 in {0..255}; do

      lkp1a=$( bpftool map lookup name crc_lookup_tbl1 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp1a=${calc_tbl[$index2]}
      ((lkp1b=lkp1a & 0xFF))
      calc=$(printf "%08x" $lkp1b)
      #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
      #lkp1c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp1c=${calc_tbl[$lkp1b]}
      ((ins=(lkp1a >> 8) ^ lkp1c))
      #printf "lkp1b = %0x\n" $lkp1b
      #echo "index2= $(printf "%x" $index2)"
      calc_tbl2[index2]=$ins
      calc2=$(printf "%08x" $ins)
      TABLE2+="${calc2:6:2} ${calc2:4:2} ${calc2:2:2} ${calc2:0:2} "

      #lkp2a=$( bpftool map lookup name crc_lookup_tbl2 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
      lkp2a=${calc_tbl2[$index2]}
            ((lkp2b=lkp2a & 0xFF))
            #calc=$(printf "%08x" $lkp2b)
            #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
            #lkp2c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
            lkp2c=${calc_tbl[$lkp2b]}
            ((ins2=(lkp2a >> 8) ^ lkp2c))
            #printf "lkp1b = %0x\n" $lkp1b
            #echo "index2= $(printf "%x" $index2)"
            calc_tbl3[index2]=$ins2
            calc3=$(printf "%08x" $ins2)
            TABLE3+="${calc3:6:2} ${calc3:4:2} ${calc3:2:2} ${calc3:0:2} "
      #lkp3a=$( bpftool map lookup name crc_lookup_tbl3 key hex $(printf "%x" $index2) 00 00 00 | awk 'FNR == 3 {print $2}' )
                  lkp3a=${calc_tbl3[$index2]}
                  ((lkp3b=lkp3a & 0xFF))
                  #calc=$(printf "%08x" $lkp3b)
                  #BECALC1="${calc:6:2} ${calc:4:2} ${calc:2:2} ${calc:0:2}"
                  #lkp3c=$( bpftool map lookup name crc_lookup_tbl1 key hex $calc 00 00 00 | awk 'FNR == 3 {print $2}' )
                  lkp3c=${calc_tbl[$lkp3b]}
                  ((ins3=(lkp3a >> 8) ^ lkp3c))
                  #printf "lkp1b = %0x\n" $lkp1b
                  #echo "index2= $(printf "%x" $index2)"
                  calc_tbl4[index2]=$ins3
                  calc4=$(printf "%08x" $ins3)
                  TABLE4+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "

                  lkp3a=${calc_tbl4[$index2]}
                  ((lkp3b=lkp3a & 0xFF))

                   lkp3c=${calc_tbl[$lkp3b]}
                   ((ins4=(lkp3a >> 8) ^ lkp3c))

                   calc_tbl5[index2]=$ins4
                   calc4=$(printf "%08x" $ins4)
                   TABLE5+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "

                  lkp3a=${calc_tbl5[$index2]}
                  ((lkp3b=lkp3a & 0xFF))

                   lkp3c=${calc_tbl[$lkp3b]}
                   ((ins5=(lkp3a >> 8) ^ lkp3c))

                   calc_tbl6[index2]=$ins5
                   calc4=$(printf "%08x" $ins5)
                   TABLE6+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "

                  lkp3a=${calc_tbl6[$index2]}
                  ((lkp3b=lkp3a & 0xFF))

                   lkp3c=${calc_tbl[$lkp3b]}
                   ((ins6=(lkp3a >> 8) ^ lkp3c))

                   calc_tbl7[index2]=$ins6
                   calc4=$(printf "%08x" $ins6)
                   TABLE7+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "

                  lkp3a=${calc_tbl7[$index2]}
                  ((lkp3b=lkp3a & 0xFF))

                   lkp3c=${calc_tbl[$lkp3b]}
                   ((ins7=(lkp3a >> 8) ^ lkp3c))

                   calc_tbl8[index2]=$ins7
                   calc4=$(printf "%08x" $ins7)
                   TABLE8+="${calc4:6:2} ${calc4:4:2} ${calc4:2:2} ${calc4:0:2} "




    done
    TABLE+=$TABLE2
    TABLE+=$TABLE3
    TABLE+=$TABLE4
    TABLE+=$TABLE5
    TABLE+=$TABLE6
    TABLE+=$TABLE7
    TABLE+=$TABLE8

    bpftool map update name crc_lookup_tbl key hex  00 00 00 00  value  hex $TABLE
}



__generate_crc_lookup_table3


#__generate_crc_lookup_table_standard

echo -e "Dumping BPF setup:"
bpftool net show

XDP_PROG_ID="$(bpftool prog show -f | grep xdp_func | awk '{print $1}' | tr -d : | tail -n1)"
TC_EGRESS_PROG_ID="$(bpftool prog show -f | grep tc_egress_func | awk '{print $1}' | tr -d : | tail -n1)"
TC_INGRESS_PROG_ID="$(bpftool prog show -f | grep tc_ingress_func | awk '{print $1}' | tr -d : | tail -n1)"

XLATED_XDP="$(bpftool prog dump xlated id "$XDP_PROG_ID" | grep -v ";" | wc -l)"
JITED_XDP="$(bpftool prog dump jited id "$XDP_PROG_ID" | grep -v ";" | wc -l)"

XLATED_TC_INGRESS="$(bpftool prog dump xlated id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_INGRESS="$(bpftool prog dump jited id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"

XLATED_TC_EGRESS="$(bpftool prog dump xlated id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_EGRESS="$(bpftool prog dump jited id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"

XLATED=$(( $XLATED_XDP + $XLATED_TC_INGRESS + $XLATED_TC_EGRESS ))
JITED=$(( $JITED_XDP + $JITED_TC_INGRESS + $JITED_TC_EGRESS  ))

STACK_SIZE="$(llvm-objdump -S -no-show-raw-insn out.o | grep "r10 -" | awk '{print $7}' | sort -n | tail -n1 | tr -d ")")"

echo -e "Summary of eBPF programs:"
echo -e "BPF stack size = "$STACK_SIZE""
echo -e "# of BPF insns"
echo -e "\txlated: "$XLATED""
echo -e "\tjited: "$JITED""