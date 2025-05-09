#!/usr/bin/env python3
# ===================================
# Copyright (c) Microsoft Corporation. All rights reserved.
# See license.txt for license information.
# ===================================

from contextlib import contextmanager

import subprocess
import shutil
import pwd
import grp
import os
import sys
import stat
import tempfile
import codecs
import importlib.util

spec = importlib.util.spec_from_file_location('protocol', '../protocol.py')
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)

spec = importlib.util.spec_from_file_location('nxDSCLog', '../nxDSCLog.py')
nxDSCLog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nxDSCLog)

spec = importlib.util.spec_from_file_location('helperlib', '../helperlib.py')
helperlib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helperlib)

LG = nxDSCLog.DSCLog

# 	[Key] string GetScript;
# 	[Key] string SetScript;
# 	[Key] string TestScript;
# 	[write] string User;
# 	[write] string Group;
# 	[Read] string Result;

global show_mof
show_mof = False


def Set_Marshall(GetScript, SetScript, TestScript, User, Group):
    if GetScript is None:
        GetScript = ''
    if SetScript is None:
        SetScript = ''
    if TestScript is None:
        TestScript = ''
    if User is None:
        User = ''
    if Group is None:
        Group = ''

    retval = Set(GetScript, SetScript, TestScript, User, Group)
    return retval


def Test_Marshall(GetScript, SetScript, TestScript, User, Group):
    if GetScript is None:
        GetScript = ''
    if SetScript is None:
        SetScript = ''
    if TestScript is None:
        TestScript = ''
    if User is None:
        User = ''
    if Group is None:
        Group = ''

    retval = Test(GetScript, SetScript, TestScript, User, Group)
    return retval


def Get_Marshall(GetScript, SetScript, TestScript, User, Group):
    arg_names = list(locals().keys())
    if GetScript is None:
        GetScript = ''
    if SetScript is None:
        SetScript = ''
    if TestScript is None:
        TestScript = ''
    if User is None:
        User = ''
    if Group is None:
        Group = ''

    retval = 0
    (retval, GetScript, SetScript, TestScript, User, Group,
            Result) = Get(GetScript, SetScript, TestScript, User, Group)

    GetScript = protocol.MI_String(GetScript)
    SetScript = protocol.MI_String(SetScript)
    TestScript = protocol.MI_String(TestScript)
    User = protocol.MI_String(User)
    Group = protocol.MI_String(Group)
    Result = protocol.MI_String(Result)
    arg_names.append('Result')

    retd = {}
    ld = locals()
    for k in arg_names:
        retd[k] = ld[k]
    return retval, retd


#
# Begin user defined DSC functions
#

def SetShowMof(a):
    global show_mof
    show_mof = a


def ShowMof(op, GetScript, SetScript, TestScript, User, Group):
    if not show_mof:
        return
    mof = ''
    mof += op + ' nxScript MyScript \n'
    mof += '{\n'
    mof += '    TestScript = "' + TestScript + '"\n'
    mof += '    GetScript = "' + GetScript + '"\n'
    mof += '    SetScript = "' + SetScript + '"\n'
    mof += '    User = "' + User + '"\n'
    mof += '    Group = "' + Group + '"\n'
    mof += '}\n'
    f = open('./test_mofs.log', 'a')
    Print(mof, file=f)
    f.close()


def Print(s, file=sys.stdout):
    file.write(s + '\n')


@contextmanager
def opened_w_error(filename, mode="r"):
    """
    This context ensures the file is closed.
    """
    try:
        f = codecs.open(filename, mode,'utf8')
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()


def WriteFile(path, contents):
    with opened_w_error(path, 'w') as (f, error):
        if error:
            Print("Exception opening file " + path + " Error Code: " + str(error.errno)
                    + " Error: " + error.message + error.strerror, file=sys.stderr)
            LG().Log('ERROR', "Exception opening file " + path + " Error Code: " +
                    str(error.errno) + " Error: " + error.message + error.strerror)
            return -1
        else:
            f.write(contents.replace("\r", ""))
        return 0


def GetUID(User):
    uid = None
    try:
        uid = pwd.getpwnam(User)[2]
    except KeyError:
        Print('ERROR: Unknown UID for ' + User, file=sys.stderr)
        LG().Log('ERROR', 'ERROR: Unknown UID for ' + User)
    return uid


def GetGID(Group):
    gid = None
    try:
        gid = grp.getgrnam(Group)[2]
    except KeyError:
        Print('ERROR: Unknown GID for ' + Group, file=sys.stderr)
        LG().Log('ERROR', 'ERROR: Unknown GID for ' + Group)
    return gid


# This is a function that returns a callback function.  The callback
# function is called prior to a user's script being executed
def PreExec(uid, gid, User):
    def SetIDs_callback():
        if gid is not -1:
            os.setgroups([gid])
            os.setgid(gid)
        if uid is not -1:
            os.setuid(uid)
            os.environ["HOME"] = os.path.expanduser("~" + User)
    return SetIDs_callback


class Params:

    def __init__(self, GetScript, SetScript, TestScript, User, Group):
        self.GetScript = GetScript
        self.SetScript = SetScript
        self.TestScript = TestScript
        self.User = User
        self.Group = Group
        self.Result = ''


def Set(GetScript, SetScript, TestScript, User, Group):
    ShowMof('SET', GetScript, SetScript, TestScript, User, Group)
    p = Params(GetScript, SetScript, TestScript, User, Group)
    # write out SetScript to a file, run it as User/Group, return exit code
    tempdir = TempWorkingDirectory(User, Group)
    path = tempdir.GetTempPath()
    command = path

    uid = gid = -1
    if User:
        uid = GetUID(User)
        if uid is None:
            Print('ERROR: Unknown UID for ' + User, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown UID for ' + User)
            return [-1]
    if Group:
        gid = GetGID(Group)
        if gid is None:
            Print('ERROR: Unknown GID for ' + Group, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown GID for ' + Group)
            return [-1]

    WriteFile(path, SetScript)
    os.chmod(path, stat.S_IXUSR | stat.S_IRUSR | stat.S_IXGRP | stat.S_IRGRP)
    os.chown(path, uid, gid)

    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, preexec_fn=PreExec(uid, gid, User))
    exit_code = proc.wait()

    stdoutread=proc.stdout.read().decode('utf8', 'replace')
    stderrread=proc.stderr.read().decode('utf8', 'replace')

    Print("stdout: " + stdoutread)
    LG().Log('INFO', "stdout: " + stdoutread)
    Print("stderr: " + stderrread)
    LG().Log('INFO', "stderr: " + stderrread)

    if exit_code != 0:
         LG().Log('ERROR', "############# ERROR in set-script:\n" + TestScript)

    return [exit_code]


def Test(GetScript, SetScript, TestScript, User, Group):
    # write out TestScript to a file, run it as User/Group, return exit code
    ShowMof('TEST', GetScript, SetScript, TestScript, User, Group)
    p = Params(GetScript, SetScript, TestScript, User, Group)
    tempdir = TempWorkingDirectory(User, Group)
    path = tempdir.GetTempPath()
    command = path

    uid = gid = -1
    if User:
        uid = GetUID(User)
        if uid is None:
            Print('ERROR: Unknown UID for ' + User, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown UID for ' + User)
            return [-1]
    if Group:
        gid = GetGID(Group)
        if gid is None:
            Print('ERROR: Unknown GID for ' + Group, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown GID for ' + Group)
            return [-1]

    WriteFile(path, TestScript)
    os.chmod(path, stat.S_IXUSR | stat.S_IRUSR | stat.S_IXGRP | stat.S_IRGRP)
    os.chown(path, uid, gid)

    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, preexec_fn=PreExec(uid, gid, User))
    exit_code = proc.wait()

    stdoutread=proc.stdout.read().decode('utf8', 'replace')
    stderrread=proc.stderr.read().decode('utf8', 'replace')

    Print("stdout: " + stdoutread)
    LG().Log('INFO', "stdout: " + stdoutread)
    Print("stderr: " + stderrread)
    LG().Log('INFO', "stderr: " + stderrread)


    if exit_code != 0:
         LG().Log('ERROR', "############# ERROR in test-script:\n" + TestScript)

    os.remove(path)
    return [exit_code]


def Get(GetScript, SetScript, TestScript, User, Group):
    # write out GetScript to a file, run it as User/Group, then return
    # stderr/stdout and exit code
    ShowMof('GET', GetScript, SetScript, TestScript, User, Group)
    p = Params(GetScript, SetScript, TestScript, User, Group)
    tempdir = TempWorkingDirectory(User, Group)
    path = tempdir.GetTempPath()
    command = path

    uid = gid = -1
    if User:
        uid = GetUID(User)
        if uid is None:
            Print('ERROR: Unknown UID for ' + User, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown UID for ' + User)
            return [-1, GetScript, SetScript, TestScript, User, Group, 1]
    if Group:
        gid = GetGID(Group)
        if gid is None:
            Print('ERROR: Unknown GID for ' + Group, file=sys.stderr)
            LG().Log('ERROR', 'ERROR: Unknown GID for ' + Group)
            return [-1, GetScript, SetScript, TestScript, User, Group, 1]

    WriteFile(path, GetScript)
    os.chmod(path, stat.S_IXUSR | stat.S_IRUSR | stat.S_IXGRP | stat.S_IRGRP)
    os.chown(path, uid, gid)

    proc = subprocess.Popen(command, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, preexec_fn=PreExec(uid, gid, User))
    exit_code = proc.wait()

    stdoutread=proc.stdout.read().decode('utf8', 'replace')
    stderrread=proc.stderr.read().decode('utf8', 'replace')

    Print("stdout: " + stdoutread)
    LG().Log('INFO', "stdout: " + stdoutread)
    Print("stderr: " + stderrread)
    LG().Log('INFO', "stderr: " + stderrread)

    if exit_code != 0:
         LG().Log('ERROR', "############# ERROR in get-script:\n" + GetScript)

    os.remove(path)
    return [exit_code, GetScript, SetScript, TestScript, User, Group, stdoutread]


class TempWorkingDirectory:

    def __init__(self, User, Group):
        self.dir = tempfile.mkdtemp(dir='/var/opt/omi/run')
        uid = gid = -1
        if User:
            uid = GetUID(User)
            if uid is None:
                Print('ERROR: Unknown UID for ' + User, file=sys.stderr)
                LG().Log('ERROR', 'ERROR: Unknown UID for ' + User)
                uid = -1
        if Group:
            gid = GetGID(Group)
            if gid is None:
                Print('ERROR: Unknown GID for ' + Group, file=sys.stderr)
                LG().Log('ERROR', 'ERROR: Unknown GID for ' + Group)
                gid = -1

        os.chown(self.dir, uid, gid)
        os.chmod(self.dir, stat.S_IXUSR |
                stat.S_IRUSR | stat.S_IXGRP | stat.S_IRGRP)

    def __del__(self):
        shutil.rmtree(self.dir)

    def GetTempPath(self):
        return os.path.join(self.dir, "temp_script.sh")
