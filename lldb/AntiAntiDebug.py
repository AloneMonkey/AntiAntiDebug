#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
    反反调试脚本，过了反调试后记得:
    aadebug -d
    否则会很卡，如果有定时器定时检测，建议写tweak
    """

import lldb
import fblldbbase as fb
import fblldbobjcruntimehelpers as objc

def lldbcommands():
    return [
            AMAntiAntiDebug()
            ]

class AMAntiAntiDebug(fb.FBCommand):
    def name(self):
        return 'aadebug'
    
    def description(self):
        return "anti anti debug ptrace syscall sysctl"
    
    def options(self):
        return [
                fb.FBCommandArgument(short='-d', long='--disable', arg='disable', boolean=True, default=False, help='disable anti anti debug.')
                ]
    
    def run(self, arguments, options):
        if options.disable:
            target = lldb.debugger.GetSelectedTarget()
            target.BreakpointDelete(self.ptrace.id)
            target.BreakpointDelete(self.syscall.id)
            target.BreakpointDelete(self.sysctl.id)
            print "anti anti debug is disabled!!!"
        else:
            self.antiPtrace()
            self.antiSyscall()
            self.antiSysctl()
            print "anti anti debug finished!!!"

def antiPtrace(self):
    ptrace = lldb.debugger.GetSelectedTarget().BreakpointCreateByName("ptrace")
        if is64Bit():
            ptrace.SetCondition('$x0==31')
    else:
        ptrace.SetCondition('$r0==31')
        ptrace.SetScriptCallbackFunction('sys.modules[\'' + __name__ + '\'].ptrace_callback')
        self.ptrace = ptrace

def antiSyscall(self):
    syscall = lldb.debugger.GetSelectedTarget().BreakpointCreateByName("syscall")
        if is64Bit():
            syscall.SetCondition('$x0==26 && *(int *)$sp==31')
    else:
        syscall.SetCondition('$r0==26 && $r1==31')
        syscall.SetScriptCallbackFunction('sys.modules[\'' + __name__ + '\'].syscall_callback')
        self.syscall = syscall

def antiSysctl(self):
    sysctl = lldb.debugger.GetSelectedTarget().BreakpointCreateByName("sysctl")
        if is64Bit():
            sysctl.SetCondition('$x1==4 && *(int *)$x0==1 && *(int *)($x0+4)==14 && *(int *)($x0+8)==1')
    else:
        sysctl.SetCondition('$r1==4 && *(int *)$r0==1 && *(int *)($r0+4)==14 && *(int *)($r0+8)==1')
        sysctl.SetScriptCallbackFunction('sys.modules[\'' + __name__ + '\'].sysctl_callback')
        self.sysctl = sysctl

def antiExit(self):
    self.exit = lldb.debugger.GetSelectedTarget().BreakpointCreateByName("exit")
        exit.SetScriptCallbackFunction('sys.modules[\'' + __name__ + '\'].exit_callback')

#暂时只考虑armv7和arm64
def is64Bit():
    arch = objc.currentArch()
    if arch == "arm64":
        return True
    return False

def ptrace_callback(frame, bp_loc, internal_dict):
    print "find ptrace"
    register = "x0"
    if not is64Bit():
        register = "r0"
    frame.FindRegister(register).value = "0"
    lldb.debugger.HandleCommand('continue')

def syscall_callback(frame, bp_loc, internal_dict):
    print "find syscall"
    #不知道怎么用api修改sp指向的内容QAQ
    lldb.debugger.GetSelectedTarget().GetProcess().SetSelectedThread(frame.GetThread())
    if is64Bit():
        lldb.debugger.HandleCommand('memory write "$sp" 0')
    else:
        lldb.debugger.HandleCommand('register write $r1 0')
    lldb.debugger.HandleCommand('continue')

def sysctl_callback(frame, bp_loc, internal_dict):
    module = frame.GetThread().GetFrameAtIndex(1).GetModule()
    currentModule = lldb.debugger.GetSelectedTarget().GetModuleAtIndex(0)
    if module == currentModule:
        print "find sysctl"
        register = "x2"
        if not is64Bit():
            register = "r2"
        frame.FindRegister(register).value = "0"
    lldb.debugger.HandleCommand('continue')

def exit_callback(frame, bp_loc, internal_dict):
    print "find exit"
    lldb.debugger.GetSelectedTarget().GetProcess().SetSelectedThread(frame.GetThread())
    lldb.debugger.HandleCommand('thread return')
    lldb.debugger.HandleCommand('continue')
