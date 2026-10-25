#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VMware Workstation 16.2.5 -- vstor2 (VMDK-mount) patch tool
============================================================

Drop an original installer onto this script, or put the originals next to it
and just run the script.

INPUT
-----
  arg1 (optional) : path to an ORIGINAL VMware Workstation 16.2.5 installer,
                    either the bootstrapper .exe or the bare .msi.
                    The SHA-256 is verified before anything is modified.

  If arg1 is omitted the script looks in its own folder:
      * .exe  fuzzy-matched on "vmware" and "16.2.5"
      * .msi  matched on "vmwareworkstation"  (the MSI inside the official EXE
              is called VMwareWorkstation.msi, with no version in the name)
    If both are present the EXE wins -- unless its SHA-256 is wrong, in which
    case the MSI is tried instead.

  vstor2.cab (the 16.1.2 build of the driver cabinet) must sit next to this
  script.

WHAT IT DOES
------------
  EXE input:
    * replaces the embedded VMwareWorkstation.msi with the patched one
    * optionally upgrades the bundled vcredist (see below)
    * REMOVES the Authenticode signature entirely (so the result is simply
      unsigned instead of carrying a signature that no longer validates)
    * neutralises the bootstrapper's VerifyPackageSignature() gate
    * fixes the container sizes, the certificate-table pointer and the PE
      checksum

  MSI input:
    * replaces the embedded vstor2.cab, patches the File table
      (FileSize + Version), the shared version string and MsiFileHash
    * writes "Install me with admin.cmd" and "install me.ps" next to the
      output, so the patched package is always installed from an elevated
      process

VC++ REDISTRIBUTABLE UPGRADE (EXE input only)
---------------------------------------------
  If BOTH vcredist_x86.exe and vcredist_x64.exe are next to this script, and
  BOTH have a file version greater than 14.28.29913.0 (the build bundled in
  the official installer) and lower than 15, they replace the bundled ones.

Everything is done with plain byte edits; the output is deterministic.
"""

import ctypes
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from ctypes import wintypes

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
ORIG_EXE_SHA256 = "380b0fa8a0f37ade496573cdc2ad922d3985bc83664f94431a9e513444b6c377"
ORIG_MSI_SHA256 = "a21847666ab2f8d2f81782d60e16e057709d87cd827ceab10906f3616e29d62d"
CAB_SHA256      = "7b76ce1f6782cee86bad6a86c020fdbeeabeeefdc65e91dbecc7e13c5af35970"
CAB_NAME        = "vstor2.cab"
OUT_TAG         = "vstor2_16.1.2"

# vcredist upgrade window: (14.28.29913.0, 15.0.0.0) exclusive
VC_MIN_EXCLUSIVE = (14, 28, 29913, 0)
VC_MAX_EXCLUSIVE = (15, 0, 0, 0)

# "RWMV" container
RWMV_OVERLAY   = 0x1AF800
ENTRY_NAME_LEN = 260
ENTRY_SIZE     = ENTRY_NAME_LEN + 8

# signature gate:  add esp,0x24 | cmp esi,1 | jne rel8   ->  change 75 to EB
GATE_PATTERN = bytes([0x83, 0xC4, 0x24, 0x83, 0xFE, 0x01, 0x75])

# CFBF
CFBF_SIG   = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT   = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
ALPHABET   = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
IDX        = {c: i for i, c in enumerate(ALPHABET)}

# table layouts (this MSI)
FILE_COLS   = ["File", "Component_", "FileName", "FileSize", "Version",
               "Language", "Attributes", "Sequence"]
FILE_WIDTHS = [2, 2, 2, 4, 2, 2, 2, 4]
FH_COLS     = ["File_", "Options", "HashPart1", "HashPart2", "HashPart3", "HashPart4"]
FH_WIDTHS   = [2, 2, 4, 4, 4, 4]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def die(msg):
    print("\nERROR: " + msg)
    sys.exit(1)


def read_file_version(path):
    """VS_FIXEDFILEINFO file version as a 4-tuple, or None."""
    ver = ctypes.WinDLL("version")
    ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, buf):
        return None
    p = ctypes.c_void_p()
    ln = ctypes.c_uint()
    if not ver.VerQueryValueW(buf, "\\", ctypes.byref(p), ctypes.byref(ln)):
        return None
    if ln.value < 13 * 4:
        return None
    d = struct.unpack_from("<13I", ctypes.string_at(p, 13 * 4), 0)
    return ((d[2] >> 16) & 0xFFFF, d[2] & 0xFFFF,
            (d[3] >> 16) & 0xFFFF, d[3] & 0xFFFF)


def msi_get_file_hash(path):
    """MsiGetFileHash -> 4 DWORDs (unsigned)."""
    msi = ctypes.WinDLL("msi.dll")

    class MSIFILEHASHINFO(ctypes.Structure):
        _fields_ = [("dwFileHashInfoSize", wintypes.ULONG),
                    ("dwData", wintypes.DWORD * 4)]

    msi.MsiGetFileHashW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    ctypes.POINTER(MSIFILEHASHINFO)]
    msi.MsiGetFileHashW.restype = wintypes.UINT
    info = MSIFILEHASHINFO()
    info.dwFileHashInfoSize = ctypes.sizeof(MSIFILEHASHINFO)
    if msi.MsiGetFileHashW(path, 0, ctypes.byref(info)) != 0:
        die("MsiGetFileHash failed on " + path)
    return [int(x) for x in info.dwData]


# --------------------------------------------------------------------------
# read-only MSI database access (msi.dll) -- used to locate rows reliably
# --------------------------------------------------------------------------
class MSIDB:
    def __init__(self, path):
        self.msi = ctypes.WinDLL("msi.dll")
        m = self.msi
        m.MsiOpenDatabaseW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p)]
        m.MsiOpenDatabaseW.restype = wintypes.UINT
        m.MsiDatabaseOpenViewW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                           ctypes.POINTER(ctypes.c_void_p)]
        m.MsiDatabaseOpenViewW.restype = wintypes.UINT
        m.MsiViewExecute.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        m.MsiViewExecute.restype = wintypes.UINT
        m.MsiViewFetch.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        m.MsiViewFetch.restype = wintypes.UINT
        m.MsiRecordGetStringW.argtypes = [ctypes.c_void_p, wintypes.UINT,
                                          wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        m.MsiRecordGetStringW.restype = wintypes.UINT
        m.MsiRecordGetInteger.argtypes = [ctypes.c_void_p, wintypes.UINT]
        m.MsiRecordGetInteger.restype = ctypes.c_int
        m.MsiCloseHandle.argtypes = [ctypes.c_void_p]
        m.MsiCloseHandle.restype = wintypes.UINT
        self.h = ctypes.c_void_p()
        rc = m.MsiOpenDatabaseW(path, ctypes.c_wchar_p(0), ctypes.byref(self.h))
        if rc != 0:
            die("MsiOpenDatabase failed (%d)" % rc)

    def close(self):
        if self.h:
            self.msi.MsiCloseHandle(self.h)
            self.h = None

    def query(self, sql):
        v = ctypes.c_void_p()
        if self.msi.MsiDatabaseOpenViewW(self.h, sql, ctypes.byref(v)) != 0:
            die("bad query: " + sql)
        self.msi.MsiViewExecute(v, None)
        out = []
        while True:
            rec = ctypes.c_void_p()
            rc = self.msi.MsiViewFetch(v, ctypes.byref(rec))
            if rc == 259:
                break
            if rc != 0:
                die("MsiViewFetch failed (%d)" % rc)
            out.append(rec)
        self.msi.MsiCloseHandle(v)
        return out

    def s(self, rec, i):
        buf = ctypes.create_unicode_buffer(4096)
        n = wintypes.DWORD(4096)
        if self.msi.MsiRecordGetStringW(rec, i, buf, ctypes.byref(n)) != 0:
            return None
        return buf.value

    def i(self, rec, i):
        return self.msi.MsiRecordGetInteger(rec, i)


# --------------------------------------------------------------------------
# CFBF (OLE compound file) -- read only
# --------------------------------------------------------------------------
class CFBF:
    def __init__(self, data):
        self.data = data
        if data[:8] != CFBF_SIG:
            die("not a CFBF container")
        self.sector_shift = struct.unpack_from("<H", data, 0x1E)[0]
        self.mini_shift   = struct.unpack_from("<H", data, 0x20)[0]
        self.num_dir_sec  = struct.unpack_from("<I", data, 0x28)[0]
        self.first_dir    = struct.unpack_from("<I", data, 0x30)[0]
        self.mini_cutoff  = struct.unpack_from("<I", data, 0x38)[0]
        self.first_mini   = struct.unpack_from("<I", data, 0x3C)[0]
        self.num_mini_sec = struct.unpack_from("<I", data, 0x40)[0]
        self.first_difat  = struct.unpack_from("<I", data, 0x44)[0]
        self.SS = 1 << self.sector_shift
        self.MS = 1 << self.mini_shift
        self.base = self.SS
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        sect = self.first_difat
        per = self.SS // 4 - 1
        while sect not in (ENDOFCHAIN, FREESECT) and sect != 0xFFFFFFFF:
            off = self.sector_offset(sect)
            ent = struct.unpack_from("<%dI" % (self.SS // 4), data, off)
            difat.extend(ent[:per])
            sect = ent[per]
        self.difat = [s for s in difat if s != FREESECT]
        self.fat = []
        for fs in self.difat:
            off = self.sector_offset(fs)
            self.fat.extend(struct.unpack_from("<%dI" % (self.SS // 4), data, off))
        self.minifat = []
        sect = self.first_mini
        for _ in range(self.num_mini_sec):
            if sect in (ENDOFCHAIN, FREESECT):
                break
            off = self.sector_offset(sect)
            self.minifat.extend(struct.unpack_from("<%dI" % (self.SS // 4), data, off))
            sect = self.fat[sect]
        self.entries = self._read_dir()
        self.root = self.entries[0]
        self.ministream = self._chain_bytes(self.root["start"], self.root["size"],
                                            self.SS, self.fat)

    def sector_offset(self, s):
        return self.base + s * self.SS

    def _chain_bytes(self, start, size, ssz, fat):
        out = bytearray()
        s = start
        n = 0
        if ssz == self.MS:
            while s not in (ENDOFCHAIN, FREESECT) and s < len(fat):
                o = s * self.MS
                out += self.ministream[o:o + self.MS]
                s = fat[s]
                n += 1
                if n > len(fat) + 10:
                    raise RuntimeError("chain loop")
        else:
            while s not in (ENDOFCHAIN, FREESECT) and s < len(fat):
                o = self.sector_offset(s)
                out += self.data[o:o + self.SS]
                s = fat[s]
                n += 1
                if n > len(fat) + 10:
                    raise RuntimeError("chain loop")
        return bytes(out[:size])

    def _read_dir(self):
        raw = self._chain_bytes(self.first_dir, self.num_dir_sec * self.SS, self.SS, self.fat)
        out = []
        for i in range(0, len(raw), 128):
            e = raw[i:i + 128]
            if len(e) < 128:
                break
            nl = struct.unpack_from("<H", e, 0x40)[0]
            name = e[:max(0, nl - 2)].decode("utf-16-le", "replace") if nl >= 2 else ""
            out.append({
                "idx": i // 128, "name": name, "type": e[0x42],
                "left": struct.unpack_from("<I", e, 0x44)[0],
                "right": struct.unpack_from("<I", e, 0x48)[0],
                "child": struct.unpack_from("<I", e, 0x4C)[0],
                "start": struct.unpack_from("<I", e, 0x74)[0],
                "size": struct.unpack_from("<Q", e, 0x78)[0],
            })
        return out

    def chain_of(self, start):
        out = []
        s = start
        while s not in (ENDOFCHAIN, FREESECT) and s < len(self.fat):
            out.append(s)
            s = self.fat[s]
            if len(out) > len(self.fat) + 10:
                raise RuntimeError("chain loop")
        return out

    def read_stream(self, e):
        if e["size"] < self.mini_cutoff and e["type"] == 2:
            return self._chain_bytes(e["start"], e["size"], self.MS, self.minifat)
        return self._chain_bytes(e["start"], e["size"], self.SS, self.fat)

    def live(self):
        """Directory entries reachable from root via the red-black tree."""
        out = []

        def walk(nid):
            if nid in (0xFFFFFFFF, 0xFFFFFFFE):
                return
            e = self.entries[nid]
            walk(e["left"])
            out.append(e)
            walk(e["right"])

        walk(self.root["child"])
        return out


def decode_stream_name(name):
    units = [ord(c) for c in name]
    if units and units[0] == 0x4840:      # table-stream marker
        units = units[1:]
    out = []
    for u in units:
        v = u - 0x3800
        if v < 0:
            continue
        if v >= 0x1000:
            d = v - 0x1000
            if d < 64:
                out.append(ALPHABET[d])
        else:
            d0, d1 = v % 64, v // 64
            if d0 < 64:
                out.append(ALPHABET[d0])
            if d1 < 64:
                out.append(ALPHABET[d1])
    return "".join(out)


# --------------------------------------------------------------------------
# CAB (MSCF) -- header only, enough to list names + uncompressed sizes
# --------------------------------------------------------------------------
class CabHeader:
    def __init__(self, data):
        if data[:4] != b"MSCF":
            die("not a CAB file")
        self.coffFiles = struct.unpack_from("<I", data, 16)[0]
        cFolders, cFiles = struct.unpack_from("<HH", data, 26)
        self.cFiles = cFiles
        flags = struct.unpack_from("<H", data, 30)[0]
        off = 36
        if flags & 0x0004:
            cbCFHeader, cbCFFolder, cbCFData = struct.unpack_from("<HBB", data, off)
            off += 4 + cbCFHeader
        if flags & 0x0001:
            off += 2
        if flags & 0x0002:
            for _ in range(4):
                off = data.index(b"\x00", off) + 1
        foff = self.coffFiles
        self.files = []
        for _ in range(cFiles):
            cbFile, uoff, ifolder, date, time, attribs = struct.unpack_from("<IIHHHH", data, foff)
            foff += 16
            end = data.index(b"\x00", foff)
            nm = data[foff:end].decode("cp1252", "replace")
            foff = end + 1
            self.files.append({"name": nm, "size": cbFile, "folder": ifolder})


def extract_cab(cab_path, outdir):
    exp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       "System32", "expand.exe")
    if not os.path.exists(exp):
        die("expand.exe not found (needed to unpack the cabinet)")
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run([exp, "-F:*", cab_path, outdir], capture_output=True)
    if r.returncode != 0:
        die("expand.exe failed: " + (r.stdout or b"").decode("oem", "replace"))
    return outdir


# --------------------------------------------------------------------------
# MSI patcher
# --------------------------------------------------------------------------
class MSIPatcher:
    def __init__(self, msi_path, cab_path, workdir, log=print):
        self.log = log
        self.buf = bytearray(open(msi_path, "rb").read())
        self.c = CFBF(bytes(self.buf))
        self.SS = self.c.SS
        live = self.c.live()
        self.by_idx = {e["idx"]: e for e in live}
        self.n2i = {}
        for e in live:
            if e["type"] == 2:
                self.n2i[decode_stream_name(e["name"])] = e["idx"]

        # --- analyse the replacement cabinet ---
        cab = open(cab_path, "rb").read()
        ch = CabHeader(cab)
        self.cab_names = [f["name"] for f in ch.files]
        self.cab_sizes = {f["name"]: f["size"] for f in ch.files}
        self.log("  cabinet entries:")
        for f in ch.files:
            self.log("    %-52s %8d" % (f["name"], f["size"]))

        ext = os.path.join(workdir, "cab")
        extract_cab(cab_path, ext)
        self.cab_info = {}
        for f in ch.files:
            p = os.path.join(ext, f["name"])
            if not os.path.exists(p):
                die("expand.exe did not produce " + f["name"])
            self.cab_info[f["name"]] = {
                "size": f["size"],
                "version": read_file_version(p),
                "hash": msi_get_file_hash(p),
            }
        self.new_cab = cab

        # --- read the current tables via msi.dll (row order == stream order) ---
        db = MSIDB(msi_path)
        self.file_rows = []
        for r in db.query("SELECT `File`,`FileName`,`FileSize`,`Version` FROM `File`"):
            self.file_rows.append((db.s(r, 1), db.s(r, 2), db.i(r, 3), db.s(r, 4)))
        self.fh_rows = []
        for r in db.query("SELECT `File_`,`HashPart1`,`HashPart2`,`HashPart3`,`HashPart4` FROM `MsiFileHash`"):
            self.fh_rows.append((db.s(r, 1), [db.i(r, i) for i in range(2, 6)]))
        db.close()

    # ---- low level ----
    def fat_off(self, idx):
        per = self.SS // 4
        return self.c.sector_offset(self.c.difat[idx // per]) + (idx % per) * 4

    def set_fat(self, idx, val):
        struct.pack_into("<I", self.buf, self.fat_off(idx), val)
        self.c.fat[idx] = val

    def stream_off_to_file(self, chain, off):
        return self.c.sector_offset(chain[off // self.SS]) + (off % self.SS)

    # ---- steps ----
    def replace_cab(self):
        e = self.by_idx[self.n2i["vstor2.cab"]]
        chain = self.c.chain_of(e["start"])
        old_size, new_size = e["size"], len(self.new_cab)
        n_old = len(chain)
        n_new = (new_size + self.SS - 1) // self.SS
        if n_new < n_old:
            die("replacement cabinet is smaller than the original -- not supported")
        head = n_old * self.SS
        for i, sect in enumerate(chain):
            o = self.c.sector_offset(sect)
            self.buf[o:o + self.SS] = self.new_cab[i * self.SS:(i + 1) * self.SS]
        first_new = (len(self.buf) - self.c.base) // self.SS
        if self.c.fat[first_new] != FREESECT:
            die("expected free FAT slots at the end of the file")
        tail = self.new_cab[head:]
        pad = (-len(tail)) % self.SS
        self.buf += tail + b"\x00" * pad
        n_app = (len(tail) + pad) // self.SS
        last = chain[-1]
        if self.c.fat[last] != ENDOFCHAIN:
            die("unexpected FAT chain tail")
        self.set_fat(last, first_new)
        for k in range(n_app):
            self.set_fat(first_new + k,
                         ENDOFCHAIN if k == n_app - 1 else first_new + k + 1)
        ents = self.SS // 128
        dirchain = self.c.chain_of(self.c.first_dir)
        de = (self.c.sector_offset(dirchain[e["idx"] // ents])
              + (e["idx"] % ents) * 128)
        struct.pack_into("<Q", self.buf, de + 0x78, new_size)
        self.log("  cabinet: %d -> %d bytes (%d -> %d sectors, %d appended at EOF)"
                 % (old_size, new_size, n_old, n_new, n_app))

    def _col_offsets(self, widths, nrows):
        offs, acc = [], 0
        for w in widths:
            offs.append(acc)
            acc += w * nrows
        return offs, acc

    def patch_file_table(self):
        e = self.by_idx[self.n2i["File"]]
        chain = self.c.chain_of(e["start"])
        rowsz = sum(FILE_WIDTHS)
        if e["size"] % rowsz:
            die("unexpected File table size")
        nrows = e["size"] // rowsz
        if nrows != len(self.file_rows):
            die("File table row mismatch (%d vs %d)" % (nrows, len(self.file_rows)))
        coloff, _ = self._col_offsets(FILE_WIDTHS, nrows)
        i_file = FILE_COLS.index("File")
        i_fs   = FILE_COLS.index("FileSize")
        i_ver  = FILE_COLS.index("Version")
        vw = FILE_WIDTHS[i_ver]

        patched = []
        old_version_str = None
        for row, (key, fname, size, ver) in enumerate(self.file_rows):
            if key not in self.cab_sizes:
                continue
            info = self.cab_info[key]
            # FileSize
            so = coloff[i_fs] + row * 4
            fo = self.stream_off_to_file(chain, so)
            cur = struct.unpack_from("<I", self.buf, fo)[0]
            want = info["size"] ^ 0x80000000
            if cur != want:
                struct.pack_into("<I", self.buf, fo, want)
                patched.append((fname, "FileSize", cur & 0x7FFFFFFF, info["size"]))
            # Version -> handled as a shared-string rewrite below
            if ver and info["version"]:
                if old_version_str is None:
                    old_version_str = ver
                elif old_version_str != ver:
                    die("vstor rows use different version strings; not supported")
        self.log("  File table: %d row(s) updated" % len(patched))
        for f, k, o, n in patched:
            self.log("    %-14s %s %d -> %d" % (f, k, o, n))
        return old_version_str

    def patch_version_string(self, old_ver):
        if not old_ver:
            return
        # new version comes from the .sys files in the cabinet
        new_vers = set()
        for name, info in self.cab_info.items():
            if info["version"]:
                new_vers.add(".".join(str(x) for x in info["version"]))
        if len(new_vers) != 1:
            die("cabinet .sys files have inconsistent versions: %r" % new_vers)
        new_ver = new_vers.pop()
        if len(new_ver) != len(old_ver):
            die("version string length differs (%r vs %r); cannot patch in place"
                % (old_ver, new_ver))
        e = self.by_idx[self.n2i["_StringData"]]
        chain = self.c.chain_of(e["start"])
        sdata = self.c.read_stream(e)
        n = sdata.count(old_ver.encode("ascii"))
        if n != 1:
            die("expected exactly one occurrence of %r in _StringData, found %d"
                % (old_ver, n))
        so = sdata.index(old_ver.encode("ascii"))
        fo = self.stream_off_to_file(chain, so)
        self.buf[fo:fo + len(new_ver)] = new_ver.encode("ascii")
        self.log("  version string: %r -> %r" % (old_ver, new_ver))

    def patch_filehash(self):
        e = self.by_idx[self.n2i["MsiFileHash"]]
        chain = self.c.chain_of(e["start"])
        rowsz = sum(FH_WIDTHS)
        if e["size"] % rowsz:
            die("unexpected MsiFileHash table size")
        nrows = e["size"] // rowsz
        if nrows != len(self.fh_rows):
            die("MsiFileHash row mismatch")
        coloff, _ = self._col_offsets(FH_WIDTHS, nrows)
        h1 = FH_COLS.index("HashPart1")
        cnt = 0
        for row, (key, parts) in enumerate(self.fh_rows):
            if key not in self.cab_sizes:
                continue
            new = [v ^ 0x80000000 for v in self.cab_info[key]["hash"]]
            for k in range(4):
                so = coloff[h1 + k] + row * 4
                fo = self.stream_off_to_file(chain, so)
                if struct.unpack_from("<I", self.buf, fo)[0] != new[k]:
                    struct.pack_into("<I", self.buf, fo, new[k])
            cnt += 1
            self.log("    %-14s hash updated" % key.split(".")[0])
        self.log("  MsiFileHash: %d row(s) updated" % cnt)

    def run(self):
        self.replace_cab()
        old_ver = self.patch_file_table()
        self.patch_version_string(old_ver)
        self.patch_filehash()
        return bytes(self.buf)


# --------------------------------------------------------------------------
# EXE (RWMV bootstrapper) patcher
# --------------------------------------------------------------------------
def parse_rwmv(data):
    if data[RWMV_OVERLAY:RWMV_OVERLAY + 4] != b"RWMV":
        die("no RWMV container header found at 0x%X" % RWMV_OVERLAY)
    count = struct.unpack_from("<I", data, RWMV_OVERLAY + 4)[0]
    entries = []
    off = RWMV_OVERLAY + 8
    for _ in range(count):
        name = data[off:off + ENTRY_NAME_LEN].split(b"\x00")[0].decode("latin1")
        size = struct.unpack_from("<Q", data, off + ENTRY_NAME_LEN)[0]
        entries.append({"name": name, "size": size, "hdr_off": off + ENTRY_NAME_LEN})
        off += ENTRY_SIZE
    return entries, off


def pe_checksum(path):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ckoff = e + 24 + 64
    struct.pack_into("<I", data, ckoff, 0)
    ck = 0
    for i in range(0, len(data) & ~1, 2):
        ck += data[i] | (data[i + 1] << 8)
        ck = (ck & 0xFFFF) + (ck >> 16)
    ck = (ck & 0xFFFF) + (ck >> 16)
    ck = (ck & 0xFFFF) + (ck >> 16)
    return (ck + (len(data) & 0xFFFFFFFF)) & 0xFFFFFFFF


def patch_exe(exe_path, msi_patcher, script_dir, out_path, workdir, log=print):
    src = exe_path
    if sha256_file(src) != ORIG_EXE_SHA256:
        die("input EXE does not match the expected SHA-256")

    with open(src, "rb") as f:
        head = f.read(RWMV_OVERLAY + 8 + 0x400)
    entries, payload_start = parse_rwmv(head)
    log("  container entries:")
    for en in entries:
        log("    %-26s %12d" % (en["name"], en["size"]))
    with open(src, "rb") as f:
        pe = bytearray(f.read(payload_start))

    # 1. the embedded MSI must be the original one
    msi_off = payload_start
    with open(src, "rb") as f:
        f.seek(msi_off)
        h = hashlib.sha256()
        rem = entries[0]["size"]
        while rem:
            b = f.read(min(1 << 22, rem))
            h.update(b)
            rem -= len(b)
    if h.hexdigest() != ORIG_MSI_SHA256:
        die("embedded MSI is not the expected original")

    # 2. build the patched MSI
    log("  patching the embedded MSI ...")
    tmp_msi = os.path.join(workdir, "embedded.msi")
    with open(src, "rb") as f:
        f.seek(msi_off)
        rem = entries[0]["size"]
        with open(tmp_msi, "wb") as w:
            while rem:
                b = f.read(min(1 << 22, rem))
                w.write(b)
                rem -= len(b)
    patched_msi = msi_patcher(tmp_msi, workdir)
    tmp_new = os.path.join(workdir, "patched.msi")
    with open(tmp_new, "wb") as w:
        w.write(patched_msi)
    new_msi_size = len(patched_msi)

    # 3. optional vcredist upgrade
    payloads = []
    for en in entries[1:]:
        payloads.append({"name": en["name"], "src_off": None, "size": en["size"],
                         "hdr_off": en["hdr_off"], "path": None})
    # locate each payload in the source file
    off = msi_off + entries[0]["size"]
    for p in payloads:
        p["src_off"] = off
        off += p["size"]

    for p in payloads:
        cand = os.path.join(script_dir, p["name"])
        if os.path.exists(cand):
            v = read_file_version(cand)
            if v and VC_MIN_EXCLUSIVE < v < VC_MAX_EXCLUSIVE:
                p["path"] = cand
                log("  vcredist upgrade: %s -> version %s (%d bytes)"
                    % (p["name"], ".".join(map(str, v)), os.path.getsize(cand)))
    if not (len(payloads) == 2 and all(p["path"] for p in payloads)):
        if any(p["path"] for p in payloads):
            log("  vcredist: both files must qualify -- keeping the bundled ones")
        for p in payloads:
            p["path"] = None

    # 4. assemble the new file
    log("  rebuilding the container ...")
    delta = new_msi_size - entries[0]["size"]

    # 4a. update the size field of every entry (MSI and any replaced vcredist)
    sizes = [new_msi_size]
    for p in payloads:
        sizes.append(os.path.getsize(p["path"]) if p["path"] else p["size"])
    for en, sz in zip(entries, sizes):
        struct.pack_into("<Q", pe, en["hdr_off"], sz)

    # 4b. bypass VerifyPackageSignature
    gi = pe.find(GATE_PATTERN)
    if gi < 0:
        die("signature-gate pattern not found in the bootstrapper")
    pe[gi + len(GATE_PATTERN) - 1] = 0xEB
    log("  signature gate bypassed at file offset 0x%X" % (gi + len(GATE_PATTERN) - 1))

    # 4c. certificate table -> remove
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    cert_dd = e_lfanew + 24 + 96 + 4 * 8
    old_cert_off, old_cert_sz = struct.unpack_from("<II", pe, cert_dd)
    struct.pack_into("<II", pe, cert_dd, 0, 0)
    log("  Authenticode signature removed (was %d bytes at 0x%X)"
        % (old_cert_sz, old_cert_off))

    with open(out_path, "wb") as w:
        w.write(pe)
        with open(tmp_new, "rb") as f:
            shutil.copyfileobj(f, w, 1 << 22)
        for p in payloads:
            if p["path"]:
                with open(p["path"], "rb") as f:
                    shutil.copyfileobj(f, w, 1 << 22)
            else:
                with open(src, "rb") as f:
                    f.seek(p["src_off"])
                    rem = p["size"]
                    while rem:
                        b = f.read(min(1 << 22, rem))
                        w.write(b)
                        rem -= len(b)

    # 4d. PE checksum
    ck = pe_checksum(out_path)
    with open(out_path, "r+b") as f:
        f.seek(e_lfanew + 24 + 64)
        f.write(struct.pack("<I", ck))
    log("  PE checksum recomputed (0x%08X)" % ck)
    log("  payload delta: %+d bytes" % delta)


# --------------------------------------------------------------------------
# MSI output helpers
# --------------------------------------------------------------------------
CMD_TEMPLATE = r"""@echo off
rem ===========================================================================
rem  Install the patched VMware Workstation MSI with administrator rights.
rem
rem  WHY THIS MATTERS
rem  ----------------
rem  If you simply double-click the .msi, Windows Installer elevates only at
rem  the very END of the wizard.  The client-side msiexec process that runs
rem  the immediate custom actions is NOT elevated, and the resulting
rem  installation is broken: VMware starts, but it will not accept a licence
rem  key -- not even when you later launch VMware "as administrator".
rem
rem  Running msiexec from an already-elevated process (this script) keeps the
rem  whole installation in an elevated context and avoids that problem.
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "MSI=%~dp0{msi}"
if not exist "%MSI%" (
    for %%F in ("%~dp0*.msi") do set "MSI=%%~fF"
)
if not exist "%MSI%" (
    echo ERROR: no .msi file found next to this script.
    pause
    exit /b 2
)

if exist "%~dp0vcredist_x86.exe" start /wait "" "%~dp0vcredist_x86.exe" /Q /norestart
if exist "%~dp0vcredist_x64.exe" start /wait "" "%~dp0vcredist_x64.exe" /Q /norestart

echo Installing "%MSI%" ...
msiexec.exe /i "%MSI%" /qb REBOOT=ReallySuppress
set RC=%errorlevel%
echo.
echo msiexec returned %RC%
if "%RC%"=="0" goto :done
if "%RC%"=="3010" goto :done
pause
:done
exit /b %RC%
"""

PS_TEMPLATE = r"""# install me.ps  --  install the patched VMware Workstation MSI elevated.
#
# WHY ADMIN RIGHTS ARE REQUIRED
# -----------------------------
# A plain double-click on the .msi makes Windows Installer elevate only at the
# very end of the wizard.  The client-side msiexec process that runs the
# immediate custom actions is not elevated, and the installation that results
# is broken: VMware launches, but it refuses to accept a licence key -- even
# if you later run VMware "as administrator".
#
# This script re-launches itself elevated (UAC) and then calls msiexec, so the
# entire installation runs in an elevated context.
#
# Usage:  right-click -> Run with PowerShell,  or
#         powershell -ExecutionPolicy Bypass -File "install me.ps"

$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- re-launch elevated if needed -------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Requesting administrator privileges...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $MyInvocation.MyCommand.Path + '"')
    )
    exit
}

# --- locate the MSI ---------------------------------------------------------
$msi = Get-ChildItem -Path $dir -Filter '*.msi' |
       Where-Object { $_.Name -like '*vstor2*' } |
       Select-Object -First 1
if (-not $msi) {
    $msi = Get-ChildItem -Path $dir -Filter '*.msi' | Select-Object -First 1
}
if (-not $msi) { Write-Host 'ERROR: no .msi file found next to this script.'; Read-Host; exit 2 }

# --- optional VC++ redistributables ----------------------------------------
foreach ($vc in @('vcredist_x86.exe', 'vcredist_x64.exe')) {
    $p = Join-Path $dir $vc
    if (Test-Path $p) {
        Write-Host "Installing $vc ..."
        Start-Process -FilePath $p -ArgumentList '/Q', '/norestart' -Wait
    }
}

# --- install ----------------------------------------------------------------
Write-Host ('Installing "' + $msi.FullName + '" ...')
$proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
    -ArgumentList @('/i', ('"' + $msi.FullName + '"'), '/qb', 'REBOOT=ReallySuppress') `
    -Wait -PassThru
Write-Host ('msiexec returned ' + $proc.ExitCode)
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { Read-Host 'Press Enter to close' }
exit $proc.ExitCode
"""


def write_msi_helpers(outdir, msi_name, log=print):
    cmd_path = os.path.join(outdir, "Install me with admin.cmd")
    ps_path = os.path.join(outdir, "install me.ps")
    with open(cmd_path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(CMD_TEMPLATE.format(msi=msi_name))
    with open(ps_path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(PS_TEMPLATE)
    log("  wrote: " + os.path.basename(cmd_path))
    log("  wrote: " + os.path.basename(ps_path))


# --------------------------------------------------------------------------
# input selection
# --------------------------------------------------------------------------
def pick_input(script_dir, arg):
    if arg:
        if not os.path.isfile(arg):
            die("input file not found: " + arg)
        low = arg.lower()
        if low.endswith(".exe"):
            if sha256_file(arg) != ORIG_EXE_SHA256:
                die("the EXE does not match the expected original (SHA-256).\n"
                    "       expected %s\n       actual   %s"
                    % (ORIG_EXE_SHA256, sha256_file(arg)))
            return arg, "exe"
        if low.endswith(".msi"):
            if sha256_file(arg) != ORIG_MSI_SHA256:
                die("the MSI does not match the expected original (SHA-256).\n"
                    "       expected %s\n       actual   %s"
                    % (ORIG_MSI_SHA256, sha256_file(arg)))
            return arg, "msi"
        die("unsupported input type: " + arg)

    exes, msis = [], []
    for n in sorted(os.listdir(script_dir)):
        low = n.lower()
        full = os.path.join(script_dir, n)
        if not os.path.isfile(full):
            continue
        if low.endswith(".exe") and "vmware" in low and "16.2.5" in low:
            exes.append(full)
        if low.endswith(".msi") and "vmwareworkstation" in low:
            msis.append(full)

    for p in exes:
        if sha256_file(p) == ORIG_EXE_SHA256:
            return p, "exe"
    for p in msis:
        if sha256_file(p) == ORIG_MSI_SHA256:
            return p, "msi"

    die("no matching original installer found in\n       " + script_dir +
        "\n       (looked for a *vmware*16.2.5*.exe and a *vmwareworkstation*.msi)")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    script = os.path.abspath(sys.argv[0])
    script_dir = os.path.dirname(script)
    arg = sys.argv[1] if len(sys.argv) > 1 else None

    print("=" * 74)
    print(" VMware Workstation 16.2.5 -- vstor2 (VMDK mount) patch tool")
    print("=" * 74)

    cab_path = os.path.join(script_dir, CAB_NAME)
    if not os.path.isfile(cab_path):
        die("missing %s next to this script (%s)" % (CAB_NAME, script_dir))
    if sha256_file(cab_path) != CAB_SHA256:
        die("%s does not match the expected 16.1.2 cabinet (SHA-256)" % CAB_NAME)
    print("cabinet  : %s  OK" % CAB_NAME)

    src, kind = pick_input(script_dir, arg)
    print("input    : %s" % src)
    print("type     : %s" % kind.upper())

    base = os.path.splitext(os.path.basename(src))[0]
    outdir = os.path.dirname(os.path.abspath(src))
    workdir = tempfile.mkdtemp(prefix="vstor2patch_")
    try:
        def msi_patcher(msi_path, wd):
            print("  -- patching MSI: %s" % os.path.basename(msi_path))
            return MSIPatcher(msi_path, cab_path, wd).run()

        if kind == "exe":
            out = os.path.join(outdir, "%s.%s.exe" % (base, OUT_TAG))
            print("output   : %s" % out)
            patch_exe(src, msi_patcher, script_dir, out, workdir)
        else:
            out = os.path.join(outdir, "%s.%s.msi" % (base, OUT_TAG))
            print("output   : %s" % out)
            data = msi_patcher(src, workdir)
            with open(out, "wb") as f:
                f.write(data)
            write_msi_helpers(outdir, os.path.basename(out))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\ndone.")
    print("  size   : %d" % os.path.getsize(out))
    print("  sha256 : %s" % sha256_file(out))


if __name__ == "__main__":
    main()
