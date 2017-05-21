# LG LAF Protocol
This document is a reverse-engineered protocol description for LG Advanced Flash
(LAF), the download mode offered by various LG models. It is based on analysis
on the `Send_Command.exe` utility and `LGD855_20140526_LGFLASHv160.dll` file and
a USB trace using Wireshark and usbmon on Linux. Some commands were found in the
`/sbin/lafd` binary.

This document uses the following conventions for types:

 - `\xaa\xbb\xcc\xdd` denotes a byte pattern `aa bb cc dd`.
 - `0xddccbbaa` denotes a 32-bit integer in hexadecimal format. It represents
   the same byte pattern as `\xaa\xbb\xcc\xdd`.

## Overview
LAF is a simple request/response protocol operating over USB. The USB details
are described at the end of the document, the messages are described below.

Each message consists of a header, followed by an optional body. The header
contains 32-bit DWORDs, integers are encoded in little-endian form:

| Offset (hex) | Offset (dec) | Type | Description
| ----:| --:| ------- | ---
| 0x00 | 0  | char[4] | Command
| 0x04 | 4  | var     | Argument 1
| 0x08 | 8  | var     | Argument 2
| 0x0c | 12 | var     | Argument 3
| 0x10 | 16 | var     | Argument 4
| 0x14 | 20 | int     | Body length
| 0x18 | 24 | int     | CRC-16
| 0x1c | 28 | char[4] | Bit-wise invertion of command at offset 0

Arguments can be integers or character sequences depending on the command.

The CRC field is the CRC-16-CCITT calculation (LSB-first) over the header and
the body with zeroes in place of CRC.

Each request is followed by a response with a matching command field. If an
error occurs, the response contains command is `FAIL` with argument 1 being the
error code and the original request header as body.

## Commands

### OPEN - Open File
Opens a file path.

Arguments:
 - arg1 (response): DWORD file descriptor.
Request body: NUL-terminated file path that should be opened for reading or an
 empty string to open `/dev/block/mmcblk0` in read/write mode.
(at most 276 (0x114) bytes?)

Non-existing files result in FAIL with error code 0x80000001.

### CLSE - Close File
Closes a file descriptor which was returned by the `OPEN` command.

Arguments:
 - arg1: DWORD file descriptor (same in request and response).

Note: this allows you to close any file descriptor that are in use by the `lafd`
process, not just the one returned by `OPEN`. You can discover the current file
descriptors via `ls -l /proc/$pid/fd` where `$pid` is found by `ps | grep lafd`.

### HELO - Hello
Arguments:
 - arg1: DWORD Protocol Version (`\1\0\0\1`) (resp must match req.)
 - arg2 (response): Minimum Protocol Version (`\0\0\x80\0` was observed)

### CTRL - Control
Arguments:
 - arg1: "RSET" (reboots device), "POFF" (powers device off) or "ONRS"

Note: `CTRL(RSET)` with no body is sent by the `Send_Command.exe` utility for
the `LEAVE` command.

LG Flash DLL waits 5000 milliseconds after this command.

### WRTE - Write File
Writes to a file descriptor.

Arguments:  See Request and Response below.

Request body: the data to be written.

#### Request

Arguments:
 - arg1: File descriptor (See `OPEN`).
 - arg2: Starting offset in **512-byte blocks**.
   > **Note:**  When writing a partition, `/sys/block/sdX/sdXN/start` refers to the **sector** offset, expressed in bytes of size `/sys/block/sde/queue/logical_block_size`, which is probably 4096.
   
   > **Example:** On the H872, `recovery` is mounted to `sde2`.  `/sys/block/sde/sde2/start` shows a value of `81962` for this partition's start sector.  To begin writing at this point, `arg2` would need to be `(81962 / 8) = 10246`, or `0x2806`, or `\x06\x28\0\0`.
 - arg3: None. (`\0\0\0\0`)
 - arg4: Continuation Type:
   - **`0x38` (`\x38\0\0\0`):** This is not a continuation of a previous `WRTE` and there will not be a continuation of this `WRTE`.  In other words, this is the only `WRTE` for this particular file / partition / other data chunk.
   - **`0x18` (`\x18\0\0\0`):** This is not a continuation of a previous `WRTE` and there will be a continuation of this `WRTE`.  In other words, this is first in a series of `WRTE` commands for a single file / partition / other data chunk.
   - **`0x09` (`\x09\0\0\0`):** This is a continuation of a previous `WRTE` and there will be a continuation of this `WRTE`.  In other words, this is neither the first nor is it the last in a series of `WRTE` commands for a single file / partition / other data chunk.
   - **`0x29` (`\x29\0\0\0`):** This is a continuation of a previous `WRTE` and there will not be a continuation of this `WRTE`.  In other words, this is last in a series of `WRTE` commands for a single file / partition / other data chunk.

#### Body length

Note that, when inspecting a packet capture of a `WRTE` operation, the `len` portion of the LAF header for a `WRTE` where the value of `arg4` is `0x18` will be larger than the actual packet itself.  The `len` portion of the header refers to the total amount of data that is to be written, and this will, in this case, be split over several packets.  Thus, a `WRTE` response will not be received, nor will it be expected, until the entire `len` bytes has been writen.

#### Response

Writing to a file descriptor which was opened for reading results in FAIL with code 0x82000002.

Note:  Integer overflow in the response offset is ignored. That is, the block offset 30736384 (0x1d50000) is 0x3aa000000 bytes, but will appear as 0xaa000000.

Arguments:
 - arg1: File descriptor sent with request.
 - arg2: Starting offset, as `arg2` of the request, in **bytes**.  Assuming a logical sector size of 4096, `arg2 / 4096` should equal the value of `arg2` that was sent with the request.
 - arg3: Unsure?  This has always been observed sending a value of `0x08` or `\x08\0\0\0`.
 - arg4: `0x01` (`\x01\0\0\0`) if the request was a continuation, `0x00` (`\0\0\0\0`) if not.  See `arg4` of the request for details.

### READ - Read File
Reads from a file descriptor.

Arguments:
 - arg1: file descriptor.
 - arg2: offset in **blocks** (multiple of 512 bytes).
 - arg3: requested length in bytes (at most 8MiB).
 - arg4: "whence" seek mode (see below).
Response body: data in file at given offset and requested length.

Note: be sure not to read past the end of the file (512 * offset + length), this
will hang the communication, requiring a reset (pull out battery)!

Arg4 affects the seek mode, values for request:
 - 0 (`SEEK_SET`) - seek to `512 * offset`.
 - 1 (`SEEK_CUR`) - read from current position (offset argument is ignored).
 - 2 (`SEEK_END`) - kind of useless when all offsets are unsigned...
 - 3 (`SEEK_DATA`) - FAILs with 0x80000001 when used on `/proc/kmsg` or
   `/dev/block/mmcblk0p44`. Works on a regular file though.
The response matches the request (masked with 0x3).

If the length is larger than somewhere between 227 MiB and 228 MiB, an
0x80000001 error will be raised (observed with /dev/block/mmcblk0). Requesting
lengths larger than 8 MiB however already seem to hang the communication.

### ERSE - Erase Block
TRIMs a block (`IOCTL_TRIM_CMD`).

Arguments:
 - arg1: file descriptor (open `/dev/block/mmcblk0` for writing).
 - arg2: start address (in sectors).
 - arg3: count (in sectors).
 - arg4: unknown, set to zero.
Request body: none.

Note: after sending TRIM, reading the block still returned old values. After a
reboot, everything was zeroed out though.

### EXEC - Execute Command
Arguments: none
Request body: NUL-terminated command, at most 255 bytes including terminator.
Response body: standard output of the command.

The command is split on spaces and then passed to `execvp`. In order to see
standard error, use variables and globbing, use a command such as:

    sh -c eval\t"$*"</dev/null\t2>&1 -- echo $PATH

(replace `\t` by tabs)

If you need to read dmesg (or other blocking files), try to put busybox on the
device (e.g. by writing to an unused partition) and execute:

    /data/busybox timeout -s 2 cat /proc/kmsg

The maximum output size appears to be 0x800001 (`LAF_MAX_DATA_PAYLOAD`). Larger
values result in an error. Output is read per byte, not very efficient for large
output...

### INFO
Arguments:
 - arg1: action (`GPRO` - Get Properties, `SPRO` - Set Properties)
Request body: a `laf_property` structure.
Response body: 2824 (0x00000b08) bytes of binary info.

See [scripts/parse-props.py](scripts/parse-props.py) for the structure of the
property body. This structure begins with a DWORD with a version that is
apparently the same as the expected length (2824 or `\x08\x0b\0\0`).

### UNLK - Unlink
Delete a file.

Arguments: none
Request body: NUL-terminated file name

Responds with FAIL code 0x80000001 if the file name is invalid (missing) or
file does not exist. Deleting directories is also not possible, giving the same
FAIL code 0x80000001.

### RSVD - Reserved
Arguments: none

### IOCT - ioctl
Unknown.

### MISC
Unknown.

### KILO
Unknown.

### DIFF
Unknown.

### SIGN
Arguments: none

Request body: 82,448 bytes of binary data.

The following was observed in the SIGN body while flashing a KDZ to a G6 using LGUP:

- The first 16 bytes appear to be a command, or possibly options or attributes?
> Example:

        99:07:43:53:00:10:00:00  3d:01:00:00:00:01:00:00

- The next 256 bytes are possibly a public key?
- The next 256 bytes are all set to `0xff`
- The next 25,360 bytes "touch" some partitions (see below).  These 25,360 bytes consist of 317 iterations of a particular 80-byte sequence:
  - Bytes 1 - 28 are the partition name and padding with trailing bytes set to 0x00.
  - Bytes 29 - 32 are set to 0xff
    > Example:

        73:79:73:74:65:6d:00:00  00:00:00:00:00:00:00:00
        00:00:00:00:00:00:00:00  00:00:00:00:ff:ff:ff:ff
  - The next 8 bytes and the following 8 bytes appear to be some kind of identifier, flags, or attributes.  They tend to contain 1 to 3 bytes each of data, and are `0x00`-padded.
    > Example:

        de:af:02:00:00:00:00:00  aa:7c:00:00:00:00:00:00

  - The final 32 bytes of this sequence "do something."  Maybe a digest hash?
    > Example:

        53:dd:90:1c:50:c1:ea:16  43:4d:38:c6:49:ca:39:4c
        83:b1:38:95:c5:9f:3c:06  fc:a7:ac:54:d3:ac:c9:58

  - The final 56,560 bytes of the SIGN request body are all set to `0xff`
 
 > The partitions that were "touched" by the SIGN command, in order, were:
> `PrimaryGPT, laf, lafbak, misc, factory, rct, persist, system (56 times), cache (16 times), userdata (194 times), BackupGPT, PrimaryGPT, xbl, xblbak, BackupGPT, PrimaryGPT, xbl2, xbl2bak, BackupGPT, PrimaryGPT, BackupGPT, PrimaryGPT, boot, recovery, recoverybak, tz, tzbak, aboot, abootbak, raw_resources, raw_resourcesbak, rpm, rpmbak, hyp, hypbak, pmic, pmicbak, devcfg, devcfgbak, modem, sec, keymaster, keymasterbak, cmnlib, cmnlibbak, cmnlib64, cmnlib64bak, apdp, msadp, BackupGPT, PrimaryGPT, BackupGPT, PrimaryGPT, BackupGPT`

## USB layer
The LG Windows driver (via `LGMobileDriver_WHQL_Ver_4.0.3.exe`) exposes two
serial ports, `LGANDNETMDM0` and `LGANDNETDIAG1`. The `LGANDNETDIAG1` port is
used for LAF.

The LG G3 (D855) has Vendor ID 0x1004 and Product ID 0x633e.

There is only one configuration descriptor and LAF uses bulk transfers over
endpoints 5 (for input from the device) and endpoint 3 (for output to the
device).

For other descriptors, see [info/lsusb.txt](info/lsusb.txt).
