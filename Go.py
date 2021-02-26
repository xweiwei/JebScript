# -*- coding: utf-8 -*-
#?description=Jump from an activity name (selected in the Android XML Manifest) to its corresponding bytecode definition in the DEX disassembly fragment
#?shortcut=Ctrl+Shift+G
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.android.dex import IDexMethod, DexPoolType

"""
Sample script for JEB Decompiler.
This JEB UI script allows the user to jump from an activity name (selected in the Android XML
Manifest) to its corresponding bytecode definition in the DEX disassembly fragment.
"""
class Go(IScript):

    def run(self, ctx):
        self.prj = ctx.getMainProject()
        assert self.prj, 'Need a project'

        if not isinstance(ctx, IGraphicalClientContext):
            print('This script must be run within a graphical client')
            return
        fv = ctx.getFocusedView()
        focus_text = ''
        if fv != None:
            self.fragment = fv.getActiveFragment()
            print('active address {}'.format(self.fragment.getActiveAddress()))
            focus_text = self.fragment.getActiveItemAsText()

            if self.fragment.getUnit().getName() == 'Manifest':
                self.go_to_activity(ctx, focus_text)

        go_str = ctx.displayQuestionBox("go where",
                                           "class(eg. a.b.c, La/b/c;), method(eg. 'a.b.c.a( La/b/c;->a('), method match(eg. 'a.b.c.a*('):",
                                           focus_text)
        if not go_str:
            print ('Please input something')
            return

        self.dex = self.prj.findUnits(IDexUnit)[0]

        self.go(ctx, go_str)

        print('[*] Go Script End')

    def go(self, ctx, go_str):
        if '(' in go_str:
            self. go_to_method(ctx, go_str)
        else:
            self.go_to_class(ctx, go_str)

    def go_to_address(self, ctx, address):
        unit = RuntimeProjectUtil.findUnitsByType(self.prj, IDexUnit, False).get(0)
        if not unit:
            print('The DEX unit was not found')
            return

        ctx.openView(unit)
        # this code assumes that the active fragment is the disassembly (it may not be; strong script should focus the assembly fragment)
        ctx.getFocusedView().getActiveFragment().setActiveAddress(address)

    def go_to_activity(self, ctx, aname):
        fragment = self.fragment
        prj = self.prj
        # make sure that the fragment has the focus, els the item would not be considered active

        if not aname:
            print('Select the activity name')
            return

        # activity name is relative to the package name
        if aname.startswith('.'):
            # unit is the Manifest, of type IXmlUnit; we can retrieve the XML document
            # note: an alternate way would be to retrieve the top-level IApkUnit, and use getPackageName()
            dom = fragment.getUnit().getDocument()
            pname = dom.getElementsByTagName("manifest").item(0).getAttribute("package")
            #print('Package name: %s' % pname)
            aname = pname + aname

        print('Activity name: %s' % aname)

        addr = 'L' + aname.replace('.', '/') + ';'
        print('Target address: %s' % addr)

        unit = RuntimeProjectUtil.findUnitsByType(prj, IDexUnit, False).get(0)
        if not unit:
            print('The DEX unit was not found')
            return

        ctx.openView(unit)
        # this code assumes that the active fragment is the disassembly (it may not be; strong script should focus the assembly fragment)
        ctx.getFocusedView().getActiveFragment().setActiveAddress(addr)

    def go_to_class(self, ctx, class_name):
        if class_name[0] == 'L' and class_name[-1] == ';':
            addr = class_name
        else:
            addr = 'L' + class_name.replace('.', '/') + ';'

        self.go_to_address(ctx, addr)


    def go_to_method(self, ctx, method_str):
        assert isinstance(method_str, unicode)
        if method_str[0] != 'L':
            r_index = method_str.rfind('.')
            class_name = method_str[: r_index]
            class_name = self.class_to_sig(class_name)
            method_name = method_str[r_index + 1:]
        else:
            method_sig_splits = method_str.split('->')
            class_name = method_sig_splits[0]
            method_name = method_sig_splits[1]

        if '*' in method_name:
            method_name = method_name.split('*')[0]

        method_sig = '{}->{}'.format(class_name, method_name)
        print('try go to method sig {}'.format(method_sig))
        methods = []
        has_body = False
        clz = self.dex.getClass(class_name)
        if clz:
            has_body = True
            for dex_method in clz.getMethods():
                assert isinstance(dex_method, IDexMethod)
                dex_method_sig = dex_method.getSignature()
                if dex_method_sig.startswith(method_sig):
                    methods.append(dex_method_sig)
        else:
            for m in self.dex.getMethods():
                assert isinstance(m, IDexMethod)
                dex_method_sig = m.getSignature()
                if dex_method_sig.startswith(method_sig):
                    methods.append(dex_method_sig)

        if len(methods) == 0:
            print('not found method {}'.format(method_str))
        else:
            print('\n[*] select a method sig in list')
            for m in methods:
                print(m)
            print('[*] method sig list end\n')

            if has_body:
                self.go_to_address(ctx, methods[0])
            else:
                decMethod = self.dex.getMethod(methods[0])
                addr_list = self.dex.getCrossReferences(DexPoolType.METHOD, decMethod.getIndex())
                addr_list_len = len(addr_list)
                if addr_list_len == 0:
                    print('not found method {}'.format(method_str))
                    return
                elif addr_list_len > 1:
                    print('list addr')
                    for addr in addr_list:
                        print(addr)
                    print('go first method call addr {}'.format(addr_list[0]))


                addr = addr_list[0]
                # 无法跳转到精确位置
                addr = str(addr).split('+')[0]
                self.go_to_address(ctx, addr)


    @staticmethod
    def class_to_sig(class_name):
        return 'L' + class_name.replace('.', '/') + ';'
