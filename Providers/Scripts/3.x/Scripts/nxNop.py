#!/usr/bin/env python
# ===================================
# Copyright (c) Microsoft Corporation. All rights reserved.
# See license.txt for license information.
# ===================================
import os
import sys

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

global show_mof
show_mof = False

# [Key] string Name;
#
# [Write, ValueMap{"Pass", "Fail"}, Values{"any value", "Fail"}] 
# string Value;
#
# [Write, ValueMap{"Present", "Absent"}, Values{"Present", "Absent"}] 
# string Ensure;

def init_vars(Name, Value, Ensure):
    if Name is None:
        Name = ''
    if Value is None or Value == '':
        Value = 'pass'
    if Ensure is None or Ensure == '':
        Ensure = 'present'
    return Name, Value.lower(), Ensure.lower()

def Set_Marshall(Name, Value, Ensure):
    (Name, Value, Ensure) = init_vars(Name, Value, Ensure)
    retval = Set(Name, Value, Ensure)
    return retval

def Test_Marshall(Name, Value, Ensure):
    (Name, Value, Ensure) = init_vars(Name, Value, Ensure)
    retval = Test(Name, Value, Ensure)
    return retval    

def Get_Marshall(Name, Value, Ensure):
    arg_names = list(locals().keys())
    (Name, Value, Ensure) = init_vars(Name, Value, Ensure)
    retval = 0
    (retval, Name, Value, Ensure) = Get(Name, Value, Ensure)
    Name = protocol.MI_String(Name)
    Value = protocol.MI_String(Value)
    Ensure = protocol.MI_String(Ensure)
    
    retd = {}
    ld = locals()
    for k in arg_names:
        retd[k] = ld[k]
    return retval, retd


class Params:

    def __init__(self, Name, Value, Ensure):
        if not ("present" in Ensure or "absent" in Ensure):
            LG().Log('ERROR', 'ERROR: Param Ensure must be "Present" or "Absent".')
            raise Exception('BadParameter')

        self.Ensure = Ensure

        if len(Name) < 1:
            LG().Log('ERROR', 'ERROR: Param Name must be set.')
            raise Exception('BadParameter')

        self.Name = Name
        self.Value = Value

############################################################
# DSC functions
############################################################
def SetShowMof(a):
    global show_mof
    show_mof = a

def ShowMof(op, Name, Value, Ensure):
    if not show_mof:
        return
    mof = ''
    mof += op + ' nxNop MyNop \n'
    mof += '{\n'
    mof += '    Name = "' + Name + '"\n'
    mof += '    Value = "' + Value + '"\n'
    mof += '    Ensure = "' + Ensure + '"\n'
    mof += '}\n'
    f = open('./test_mofs.log', 'a')
    Print(mof, file=f)
    f.close()

def Set(Name, Value, Ensure):
    retval = -1
    try:
        p = Params(Name, Value, Ensure)
    except Exception as e:
        LG().Log('ERROR', 'ERROR - Unable to initialize nxNopProvider. ' + str(e))
        return [retval]

    if p.Ensure == 'present':
        if p.Value == 'fail':
            LG().Log('ERROR', 'ERROR - Failing Set(present) due to Value = "fail".' + str(e))
        else:
            retval = 0
    else:
        if p.Value == 'fail':
            LG().Log('ERROR', 'ERROR - Failing Set(absent) due to Value = "fail". ' + str(e))
        else:
            retval = 0

    return [retval]

def Test(Name, Value, Ensure):
    retval = -1
    try:
        p = Params(Name, Value, Ensure)
    except Exception as e:
        LG().Log('ERROR', 'ERROR - Unable to initialize nxNopProvider. ' + str(e))
        return [retval]

    if p.Value == 'pass':
        retval = 0

    return [retval]

def Get(Name, Value, Ensure):
    retval = -1
    try:
        p = Params(Name, Value, Ensure)
        retval = 0       
    except Exception as e:
        LG().Log('ERROR', 'ERROR - Unable to initialize nxNopProvider. ' + str(e))

    return [retval, Name, Value, Ensure]

def Print(s, file=sys.stdout):
    file.write(s + '\n')
