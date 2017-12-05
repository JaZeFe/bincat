import sys
import os
import idaapi

# Helper function to get a filename as a Unicode string
def string_decode(string):
    if idaapi.get_kernel_version()[0] == '7':
        # IDA 7 only has UTF-8 strings
        string_u = string.decode('UTF-8')
    else:
        # IDA 6 uses the system locale
        # on Linux it's usually UTF-8 but we can't be sure
        # on Windows getfilesystemencoding returns "mbcs"
        # but it decodes cpXXXX correctly apparently
        string_u = string.decode(sys.getfilesystemencoding())
    return string_u

def safe_askfile(*args):
    # IDA 6/7 compat
    askfile = idaapi.ask_file if hasattr(idaapi, 'ask_file') else idaapi.askfile_c
    fname = askfile(1, None, "Save remapped binary")
    return string_decode(fname)

def safe_get_input_file_path():
    return string_decode(idaapi.get_input_file_path())

def guess_file_path():
    # try to use idaapi.get_input_file_path
    filepath = safe_get_input_file_path()
    if os.path.isfile(filepath):
        return filepath
    # get_input_file_path returns file path from IDB, which may not
    # exist locally if IDB has been moved (eg. send idb+binary to
    # another analyst)
    filepath = string_decode(idc.GetIdbPath().replace('idb', 'exe'))
    if os.path.isfile(filepath):
        return filepath
    # give up
    return None
