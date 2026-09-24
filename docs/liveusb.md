# Running proskrnl from a USB stick (LIVE-1)

`make liveusb` builds **`build/proskrnl-liveusb.img`**, a disk image you write
raw onto a USB drive. It boots on a real x86-64 PC — UEFI or legacy BIOS —
into the same desktop `make rungui` shows: Wine's explorer as the shell, plus
the applet shelf (notepad, wordpad, regedit, winefile, taskmgr, clock,
winver, winhlp32, progman, winemine, and their 32-bit twins through WOW64).

How it works, in one paragraph: the stick is a GPT disk whose EFI system
partition holds Limine (BIOS stage + `EFI/BOOT/BOOTX64.EFI`), the kernel,
and `liveusb-system.img` — the whole system disk as a single file. The
firmware reads the stick through its *own* USB driver, Limine loads the
system disk into RAM as the boot module tagged `memdisk`, and the kernel
mounts that RAM copy as `C:` (`drivers/memdisk.c`). The kernel never
touches the stick again, so it needs no USB mass-storage driver. **Every
write goes to RAM and is gone at power-off**; the stick is never written.
See `docs/02-milestones.md` "LIVE-1" and `docs/03-nt-deviations.md`
"LIVE-1 notes".

## 1. Build the image (Linux)

```sh
tools/setup_linux.sh          # once: toolchain + pinned third_party builds
make liveusb                  # -> build/proskrnl-liveusb.img (~290 MiB)
```

(In an ephemeral container run `tools/fetch_third_party.sh` first, as for
any build.)

## 2. Try it in QEMU first (optional, recommended)

```sh
make runlive                  # boots the image AS a USB stick, SeaBIOS
FIRMWARE=uefi make runlive    # the same through UEFI (edk2), like most PCs
```

`runlive` is `make rungui` booted the way a real box boots the stick: the
image is a `usb-storage` device on a `qemu-xhci` controller, the keyboard
and mouse are USB HID devices on the same controller, and there is no
virtio device of any kind. The mouse is a relative device: click into the
window to grab the pointer, Ctrl-Alt-G releases it.

## 3. Write it to a USB drive

**This erases the whole drive.** Any stick of 512 MB or more works.

1. Plug the stick in and find its device name. Look for `TRAN` = `usb` and
   a size that matches your stick:

   ```sh
   lsblk -d -o NAME,SIZE,MODEL,TRAN
   ```

   Below, `/dev/sdX` stands for that device — the **whole disk** (`sdb`),
   not a partition (`sdb1`). Double-check it: writing to the wrong device
   destroys that disk.

2. Unmount anything the desktop auto-mounted from it:

   ```sh
   sudo umount /dev/sdX?* 2>/dev/null
   ```

3. Write the image and flush it:

   ```sh
   sudo dd if=build/proskrnl-liveusb.img of=/dev/sdX bs=4M conv=fsync oflag=direct status=progress
   sync
   ```

4. Optional: the image's backup GPT header sits at the end of the *image*,
   not of the stick, which `fdisk`/`gdisk` will point out. Firmware boots it
   either way; to tidy it, move the backup header to the end of the device:

   ```sh
   sudo sgdisk -e /dev/sdX
   ```

5. Eject it: `sudo eject /dev/sdX`.

## 4. Boot your machine from it

1. **Disable Secure Boot** in the firmware setup. Limine's `BOOTX64.EFI` is
   not signed, so a Secure Boot machine refuses to start it.
2. Plug in a **USB keyboard and USB mouse** (see "Hardware" below — a
   laptop's built-in keyboard and touchpad will *not* work).
3. Open the firmware's one-time boot menu (commonly F12, F11, F8, F10 or
   Esc at power-on) and choose the USB stick — its **UEFI** entry if both a
   UEFI and a legacy entry are offered.
4. Limine boots immediately (no menu). The kernel's boot log scrolls on the
   screen; the first boot of every session then runs Wine's `wineboot`
   (nothing survives a power-off, so every boot is a first boot), and the
   explorer desktop comes up. Budget at least **2 GiB of RAM**: 256 MiB of
   it is the system disk.
5. To finish, shut down from the desktop or just power the machine off —
   nothing needs saving, because nothing can be saved.

## Hardware: what works and what does not

The kernel drives only the hardware it has drivers for, and real PCs are
far less uniform than QEMU. What this first milestone supports:

| Area | Supported | Not (yet) |
| --- | --- | --- |
| CPU | x86-64, one core used (uniprocessor by design, `docs/18`) | — |
| Firmware | UEFI (Secure Boot off) and legacy BIOS/CSM | Secure Boot |
| Display | the linear framebuffer the firmware/Limine set up (GOP / VBE) | GPU drivers, mode changes. The desktop is 1280x800; on a larger screen it occupies the top-left corner |
| Keyboard / mouse | USB HID **boot-protocol** devices on an **xHCI** controller on PCI bus 0, plugged into a **root port** | PS/2 and laptop built-in keyboards (i8042), I2C-HID touchpads, devices behind a USB hub (including hubs inside docks, monitors and some keyboards), report-descriptor-only HID devices (most tablets/pens), hot-plug: plug the devices in **before** booting |
| Storage | none needed: `C:` is the RAM copy | your internal disks are never touched |
| Network, sound | — | the kernel has virtio drivers only, so a real NIC or sound card is ignored |
| Power | ACPI S5 power-off | sleep, reboot through ACPI |

If input does not work, the most likely cause is a hub between the device
and the controller: many desktops route front-panel ports through an
internal hub, and many keyboards contain one. Try a rear port (on the
motherboard itself) and a plain keyboard/mouse.

## Troubleshooting

- **Stuck at `limine: Loading module ...liveusb-system.img`** — the firmware
  is reading 256 MiB through its USB driver. Legacy BIOS USB can take a
  minute or more on some boards; UEFI is usually much faster.
- **A `[PANIC]` screen** — the kernel stops loudly rather than guess
  (`docs/09` Art. 12). A photo of the screen is the bug report: the dump
  names the thread, the faulting address and the stack. If the machine has a
  serial port (COM1, 115200 8N1), the same text is on it.
- **No input** — see "Hardware" above. The serial log (or the boot screen)
  says what the USB driver found: `usb-hid: port N slot M: ...` per device.
- **Black screen after Limine** — the firmware set no linear framebuffer.
  Try the other boot entry (UEFI vs. legacy).
