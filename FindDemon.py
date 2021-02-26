# -*- coding: utf-8 -*-

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType, IDexAddress, IDexMethod
from com.pnfsoftware.jeb.core.util import DecompilerHelper

import json
import xml.etree.ElementTree as ET
# import sys
# reload(sys)
# sys.setdefaultencoding('utf-8')

'''
## Usage
find . -name '*.apk' |xargs -n 1 -I{} ~/opt/jeb-pro-3.19.1.202005071620/jeb_macos.sh -c --srv2 --script=/Users/weiwei/opt/JebScript/FindDemon.py -- {} config.json

## Config
```json
{
    "string": [
        "com.xxx.xxx.xxx.xxx",
    ],
    "method": [
        "Lcom/xxx/xxx/xxx/xxx;->getService"
    ],
    "method_to_string": true,
    "ref_count": 1,
    "refind": false
}
```
'''

class Config(object):
    def __init__(self, config_path):
        self.ref_count = 1
        self.method_to_string = False
        self.refind = False
        self.method_demons = None
        self.string_demons = None
        self.config_path = config_path
        self.load()

    def load(self):
        with open(self.config_path, 'r') as f:
            config = json.load(f)
        if 'ref_count' in config:
            self.ref_count = config['ref_count']
        if 'refind' in config:
            self.refind = config['refind']
        if 'method_to_string' in config:
            self.method_to_string = config['method_to_string']
        if 'method' in config:
            self.method_demons = config['method']
        if 'string' in config:
            self.string_demons = config['string']


class FindDemon(IScript):
    # ctx: IClientContext or IGraphicalClientContext
    def run(self, ctx):
        self.ctx = ctx

        argv = ctx.getArguments()
        if len(argv) < 2:
            print('[-] Error: Provide an input file and config')
            return

        self.inputPath = argv[0]
        self.configPath = argv[1]
        self.config = Config(self.configPath)

        print('Processing file: ' + self.inputPath + ' to find demons')

        ctx.open(self.inputPath)
        self.showPackageInfo(ctx)

        prj = ctx.getMainProject()

        dex = prj.findUnits(IDexUnit)[0]
        self.dex = dex
        # self.cstbuilder = prj.findUnits(IJavaSourceUnit)[0].getFactories().getConstantFactory()
        self.decomp = DecompilerHelper.getDecompiler(dex)

        self.findDemon()

    def findDemon(self):
        # 支持重新载入config进行查找，减少重复解析apk的过程
        while True:
            method_demons = self.config.method_demons
            if method_demons:
                self.appendMethod(method_demons)
                method_demons = list(set(method_demons))
                self.findMethodDemon(method_demons, self.config.ref_count)
            if self.config.string_demons:
                string_demons = self.config.string_demons
                if self.config.method_to_string:
                    self.method2Str(method_demons, string_demons)
                string_demons = list(set(string_demons))
                self.findStrDemon(string_demons, self.config.ref_count)
            if self.config.refind:
                while True:
                    yes = raw_input('Reload config to find demon? [y/n] ')
                    if yes == 'y':
                        try:
                            self.config.load()
                        except Exception as e:
                            print(e)
                            continue
                        break
                    elif yes == 'n':
                        return
                    else:
                        print('input error')
                        continue

            return


    def appendMethod(self, methods):
        match_methods = []
        for method_sig in methods:
            # 方法未闭合
            if ')' not in method_sig:
                clz = self.dex.getClass(method_sig.split('->')[0])
                if clz:
                    for dex_method in clz.getMethods():
                        # dex_method = IDexMethod
                        dex_method_sig = dex_method.getSignature()
                        if dex_method_sig.startswith(method_sig):
                            print('[*] Append method in method list ' + dex_method_sig)
                            match_methods.append(dex_method_sig)
                else:
                    # if isinstance(self.dex, IDexUnit):
                    #     pass
                    for m in self.dex.getMethods():
                        # if isinstance(m, IDexMethod):
                        #     pass
                        dex_method_sig = m.getSignature()
                        if dex_method_sig.startswith(method_sig):
                            print('[*] Append method in method list ' + dex_method_sig)
                            match_methods.append(dex_method_sig)
        methods.extend(match_methods)


    def method2Str(self, methods, strs):
        for method_sig in methods:
            clz_str = method_sig.split('->')[0][1:].replace('/', '.')[:-1]
            if clz_str not in strs:
                print('[*] Append class in string list ' + clz_str)
                strs.append(clz_str)

    def showPackageInfo(self, ctx):
        apk = ctx.getMainProject().findUnit(IApkUnit)
        # apk = IApkUnit
        if not apk:
            print('[-] Error : APK unit not found')
            return
        try:
            self.printDelimiter()
            print('Application info')
            print('\tPackageName:\t' + apk.getPackageName())
            doc = apk.getManifest().getFormatter().getPresentation(0).getDocument()
            text = TextDocumentUtil.getText(doc)
            root = ET.fromstring(text.encode("utf-8"))
            print('\tVersionName:\t' + root.attrib['{http://schemas.android.com/apk/res/android}versionName'])
            print('\tVersionCode:\t' + root.attrib['{http://schemas.android.com/apk/res/android}versionCode'])
            self.printDelimiter()
        except Exception as e:
            print('[-] Error ' + str(e))

    def printDelimiter(self):
        print('-' * 80)

    def printMsg(self, msg):
        self.printDelimiter()
        print(msg)
        self.printDelimiter()

    def findStrDemon(self, strDemons, n):
        self.printMsg('[*] start find string demon \n{}'.format(json.dumps(strDemons, indent=2)))
        for i in range(self.dex.getStringCount()):
            dexStr = self.dex.getString(i)
            try:
                dexStrValue = dexStr.getValue()
            except Exception as e:
                continue
                # import pdb
                # pdb.set_trace()
            # print(dexStr)
            for strDemon in strDemons:
                # if dexStrValue in strDemons:
                # 模糊匹配
                if strDemon in dexStrValue:
                    print('>' * 80)
                    print('[!]\n[!] found {} string\n[!]'.format(dexStrValue))
                    self.findRef(DexPoolType.STRING, i, n, '\n[string] \'{}\''.format(dexStrValue))

    def findMethodDemon(self, methodDemons, n):
        self.printMsg('[*] start find method demon \n{}'.format(json.dumps(methodDemons, indent=2)))
        for r_method in methodDemons:
            self.findMethodRef(r_method, n, '', True)

    def findMethodRef(self, methodSig, n, ref_str, start=False):
        if n > 0:
            decMethod = self.dex.getMethod(methodSig)
            if decMethod is None:
                return
            if start:
                print('>' * 80)
                print('[!]\n[!] found {} method\n[!]'.format(methodSig))
                ref_str += '\n[method] \'{}\''.format(methodSig)
            # self.dex.getCrossReferences(DexPoolType.METHOD, decMethod)
            self.findRef(DexPoolType.METHOD, decMethod.getIndex(), n, ref_str)
        else:
            print('<' * 80 + '\n')

    def findRef(self, poolType, index, n, ref_str):
        n = n - 1
        for addr in self.dex.getCrossReferences(poolType, index):
            if isinstance(addr, IDexAddress):
                r_method = str(addr).split('+')[0]
                # if r_method in references:
                #     continue
                # references.add(r_method)
                current_ref_str = '{}\n\t\t^\n\t\tcall\n\t\t^\n[method] \'{}\''.format(ref_str, addr)
                print(current_ref_str)
                print('')
                javaMethod = self.getDecompiledMethod(self.dex, r_method)
                if javaMethod is None:
                    print('[-] Error: The method was not found or was not decompiled')
                    return
                text = self.decomp.getDecompiledMethodText(r_method)
                print('/' + '*' * (n + 1))
                for line in text.split('\n'):
                    print((' ' * (n + 1)) + ' ' + line)
                print('*' * (n + 1) + '/')
                self.findMethodRef(r_method, n, current_ref_str)


    def getDecompiledMethod(self, dex, msig):
        print('Decompiled method sig ' + msig)
        m = self.decomp.getMethod(msig, False)
        if m is not None and m.getBody().size() > 0:
            return m

        m = dex.getMethod(msig)
        if not m:
            return None

        c = m.getClassType()
        if not c:
            return None

        decomp = DecompilerHelper.getDecompiler(dex)
        if not decomp:
            return None

        csig = c.getSignature(False)
        javaUnit = decomp.decompile(csig)
        if not javaUnit:
            return None

        m = self.decomp.getMethod(msig, False)
        if m is not None:
            print('found method {}'.format(msig))
            return m
        # msig0 = m.getSignature(False)
        # java_class = javaUnit.getClassElement()
        #
        #
        # m = self.find_method(java_class, msig0)

        # for m in javaUnit.getClassElement().getMethods():
        #     if m.getSignature() == msig0:
        #         return m
        return None
