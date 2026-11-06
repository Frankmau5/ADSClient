# -*- coding: utf-8 -*-
'''
Copyright © 2015, Robin David - MIT-Licensed
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
The Software is provided "as is", without warranty of any kind, express or implied, including but not limited
to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall
the authors or copyright holders X be liable for any claim, damages or other liability, whether in an action
of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other
dealings in the Software.
Except as contained in this notice, the name of the Robin David shall not be used in advertising or otherwise
to promote the sale, use or other dealings in this Software without prior written authorization from the Robin David.
'''
import ctypes
from ctypes import (
    Structure,
    Union,
    POINTER,
    byref,
    c_int,
    c_long,
    c_longlong,
    c_ulong,
    c_void_p,
    c_wchar,
    c_wchar_p,
)
import os
import sys

windll = getattr(ctypes, "windll", None)
kernel32 = getattr(windll, "kernel32", None) if windll is not None else None
HAS_LINUX_XATTR = hasattr(os, "listxattr") and hasattr(os, "getxattr")

LPWSTR = c_wchar_p
DWORD = c_ulong
LONG = c_long
WCHAR = c_wchar * 296
LONGLONG = c_longlong
INVALID_HANDLE_VALUE = c_void_p(-1).value


class LARGE_INTEGER_UNION(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LARGE_INTEGER(Union):
    _fields_ = [
        ("large1", LARGE_INTEGER_UNION),
        ("large2", LARGE_INTEGER_UNION),
        ("QuadPart", LONGLONG),
    ]


class WIN32_FIND_STREAM_DATA(Structure):
    _fields_ = [
        ("StreamSize", LARGE_INTEGER),
        ("cStreamName", WCHAR),
    ]
    '''
    typedef struct _WIN32_FIND_STREAM_DATA {
      LARGE_INTEGER StreamSize;
      WCHAR         cStreamName[MAX_PATH + 36];
    } WIN32_FIND_STREAM_DATA, *PWIN32_FIND_STREAM_DATA;
    '''


if kernel32 is not None:
    kernel32.FindFirstStreamW.argtypes = [
        LPWSTR,
        DWORD,
        POINTER(WIN32_FIND_STREAM_DATA),
        DWORD,
    ]
    kernel32.FindFirstStreamW.restype = c_void_p

    kernel32.FindNextStreamW.argtypes = [
        c_void_p,
        POINTER(WIN32_FIND_STREAM_DATA),
    ]
    kernel32.FindNextStreamW.restype = c_int

    kernel32.FindClose.argtypes = [c_void_p]
    kernel32.FindClose.restype = c_int


class ADS:
    """
    Cross-platform NTFS Alternate Data Stream (ADS) handler.
    - On Windows: Uses Win32 FindFirstStreamW / FindNextStreamW and 'filename:stream' syntax.
    - On Linux (mounted NTFS via ntfs-3g / ntfs3 or native ext4/btrfs/xfs):
      Uses POSIX extended attributes ('user.<stream_name>') which ntfs-3g and kernel ntfs3
      map directly to NTFS Alternate Data Streams when mounted with streams_interface=xattr (the default).
    """

    XATTR_PREFIX = "user."

    def __init__(self, filename):
        self.filename = filename
        self.stream_sizes = dict()
        self.streams = self.init_streams()

    @staticmethod
    def _extract_stream_name(raw_stream_name):
        if not raw_stream_name:
            return None
        parts = raw_stream_name.split(":")
        if len(parts) > 1 and parts[1]:
            return parts[1]
        return None

    @classmethod
    def _xattr_attr_name(cls, stream_name):
        if stream_name.startswith(cls.XATTR_PREFIX):
            return stream_name
        return f"{cls.XATTR_PREFIX}{stream_name}"

    def init_streams(self):
        streamlist = list()
        self.stream_sizes = dict()

        if kernel32 is not None:
            file_infos = WIN32_FIND_STREAM_DATA()
            myhandler = kernel32.FindFirstStreamW(
                LPWSTR(self.filename), 0, byref(file_infos), 0
            )
            if myhandler is None or myhandler == INVALID_HANDLE_VALUE:
                return streamlist

            p = c_void_p(myhandler)
            try:
                streamname = self._extract_stream_name(file_infos.cStreamName)
                if streamname:
                    streamlist.append(streamname)
                    self.stream_sizes[streamname] = file_infos.StreamSize.QuadPart

                while kernel32.FindNextStreamW(p, byref(file_infos)):
                    streamname = self._extract_stream_name(file_infos.cStreamName)
                    if streamname:
                        streamlist.append(streamname)
                        self.stream_sizes[streamname] = file_infos.StreamSize.QuadPart
            finally:
                kernel32.FindClose(p)

            return streamlist

        if HAS_LINUX_XATTR and os.path.exists(self.filename):
            try:
                attrs = os.listxattr(self.filename)
                for attr in attrs:
                    if attr.startswith(self.XATTR_PREFIX):
                        name = attr[len(self.XATTR_PREFIX):]
                    else:
                        name = attr
                    if name:
                        streamlist.append(name)
                        try:
                            val = os.getxattr(self.filename, attr)
                            self.stream_sizes[name] = len(val)
                        except OSError:
                            self.stream_sizes[name] = 0
            except OSError:
                pass

        return streamlist

    def __iter__(self):
        return iter(self.streams)

    def has_streams(self):
        return len(self.streams) > 0

    def get_stream_size(self, stream):
        if stream in self.stream_sizes:
            return self.stream_sizes[stream]
        if kernel32 is not None:
            try:
                return os.path.getsize(self.full_filename(stream))
            except OSError:
                return 0
        if HAS_LINUX_XATTR:
            try:
                return len(os.getxattr(self.filename, self._xattr_attr_name(stream)))
            except OSError:
                return 0
        return 0

    def full_filename(self, stream):
        return "%s:%s" % (self.filename, stream)

    def add_stream_from_file(self, filename, overwrite=False):
        if os.path.exists(filename):
            try:
                with open(filename, "rb") as f:
                    content = f.read()
            except OSError as e:
                print(f"Could not read file {filename}: {e}")
                return False
            return self.add_stream_from_string(
                os.path.basename(filename), content, overwrite=overwrite
            )
        else:
            print("Could not find file: {0}".format(filename))
            return False

    def add_stream_from_string(self, stream_name, string, overwrite=False):
        clean_name = os.path.basename(stream_name)
        if not clean_name:
            print("Invalid stream name")
            return False

        if isinstance(string, str):
            string = string.encode("utf-8")
        elif isinstance(string, bytearray):
            string = bytes(string)

        if kernel32 is not None:
            fullname = self.full_filename(clean_name)
            if os.path.exists(fullname) and not overwrite:
                print(f"Stream '{clean_name}' already exists (use --overwrite to replace)")
                return False

            try:
                with open(fullname, "wb") as fd:
                    fd.write(string)
            except OSError as e:
                print(f"Failed to write stream '{clean_name}': {e}")
                return False
        elif HAS_LINUX_XATTR:
            if not os.path.exists(self.filename):
                print(f"Target file '{self.filename}' does not exist")
                return False
            if clean_name in self.streams and not overwrite:
                print(f"Stream '{clean_name}' already exists (use --overwrite to replace)")
                return False
            try:
                os.setxattr(self.filename, self._xattr_attr_name(clean_name), string)
            except OSError as e:
                # Fallback for ntfs-3g mounted with streams_interface=windows
                fullname = self.full_filename(clean_name)
                try:
                    with open(fullname, "wb") as fd:
                        fd.write(string)
                except OSError:
                    print(f"Failed to write stream '{clean_name}': {e}")
                    return False
        else:
            print("ADS / extended attributes are not supported on this platform")
            return False

        if clean_name not in self.streams:
            self.streams.append(clean_name)
        self.stream_sizes[clean_name] = len(string)
        return True

    def delete_stream(self, stream):
        if kernel32 is not None:
            try:
                os.remove(self.full_filename(stream))
                if stream in self.streams:
                    self.streams.remove(stream)
                self.stream_sizes.pop(stream, None)
                return True
            except OSError:
                return False
        elif HAS_LINUX_XATTR:
            try:
                os.removexattr(self.filename, self._xattr_attr_name(stream))
                if stream in self.streams:
                    self.streams.remove(stream)
                self.stream_sizes.pop(stream, None)
                return True
            except OSError:
                # Fallback if stream was exposed without 'user.' prefix
                try:
                    os.removexattr(self.filename, stream)
                    if stream in self.streams:
                        self.streams.remove(stream)
                    self.stream_sizes.pop(stream, None)
                    return True
                except OSError:
                    return False
        return False

    def get_stream_content(self, stream):
        if kernel32 is not None:
            try:
                with open(self.full_filename(stream), "rb") as fd:
                    return fd.read()
            except OSError as e:
                print(f"Failed to read stream '{stream}': {e}")
                return b""
        elif HAS_LINUX_XATTR:
            try:
                return os.getxattr(self.filename, self._xattr_attr_name(stream))
            except OSError:
                try:
                    return os.getxattr(self.filename, stream)
                except OSError as e:
                    print(f"Failed to read stream '{stream}': {e}")
                    return b""
        return b""
