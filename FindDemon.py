# -*- coding: utf-8 -*-
import os
import traceback


from datetime import datetime

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType, IDexAddress, IDexMethod
from com.pnfsoftware.jeb.core.units.code.java import IJavaMethod
from com.pnfsoftware.jeb.core.util import DecompilerHelper

from org.w3c.dom import Document
import json
import xml.etree.ElementTree as ET
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

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
    "refind": false,
    "shared_user_id": null
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
        self.manifest_demons = None
        self.config_path = config_path
        self.shared_user_id = None
        self.name = os.path.basename(config_path).split('.')[0]
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
        if 'manifest' in config:
            self.manifest_demons = config['manifest']
        if 'shared_user_id' in config:
            self.shared_user_id = config['shared_user_id']

class Result(object):
    def __init__(self, path):
        self.path = path
        self.file = open(path, 'a')

    def write(self, msg):
        self.file.write(msg)
        self.file.write('\n')

    def close(self):
        self.file.flush()
        self.file.close()



class FindDemon(IScript):
    # ctx: IClientContext or IGraphicalClientContext
    def run(self, ctx):
        self.ctx = ctx

        argv = ctx.getArguments()
        if len(argv) < 2:
            print('[-] Error: Provide an input file and config')
            return

        self.inputPath = argv[0]

        configs = []

        # 预先加载，防止有config出错，导致后面崩溃
        for cp in argv[1:]:
            print("load config {}".format(cp))
            configs.append(Config(cp))

        # self.configPath = argv[1]
        # self.config = Config(self.configPath)

        # if len(argv) > 2:
        #     self.resultPath = argv[2]


        ctx.open(self.inputPath)
        self.showPackageInfo(ctx)

        self.ctx = ctx

        print('Processing file: ' + self.inputPath + ' to find demons')

        prj = ctx.getMainProject()

        dex = prj.findUnits(IDexUnit)[0]
        self.dex = dex
        assert isinstance(self.dex, IDexUnit)
        # self.cstbuilder = prj.findUnits(IJavaSourceUnit)[0].getFactories().getConstantFactory()
        self.decomp = DecompilerHelper.getDecompiler(dex)


        for config in configs:
            self.config = config
            self.result = None
            self.resultPath = None
            if self.config.shared_user_id:
                if self.shareUserId not in self.config.shared_user_id:
                    print('{} is not {}'.format(self.packageName, self.shareUserId))
                    continue

            self.findDemon()
            if self.result:
                self.result.close()
                self.result = None

    def output(self, msg):
        print(msg)
        if self.result is None:
            if self.resultPath:
                path = self.resultPath
            else:
                result_dir_path = 'result_{}'.format(self.config.name)
                folder = os.path.exists(result_dir_path)
                if not folder:
                    os.makedirs(result_dir_path)

                path = '{}_{}'.format(self.packageName, datetime.now().strftime("%Y%m%d%H%M%S"))
                if self.shareUserId:
                    path = '{}_{}'.format(self.shareUserId, path)
                path = '{}/{}.md'.format(result_dir_path, path)
            self.result = Result(path)
            self.outputPackageInfo()

        self.result.write(msg)


    def findDemon(self):
        # 支持重新载入config进行查找，减少重复解析apk的过程
        while True:
            method_demons = self.config.method_demons
            if method_demons:
                self.appendMethod(method_demons)
                method_demons = list(set(method_demons))
                self.findMethodDemon(method_demons, self.config.ref_count)

            if self.config.manifest_demons:
                manifest_demons = self.config.manifest_demons
                self.findStrDemonInXml(manifest_demons)

            if self.config.string_demons:
                string_demons = self.config.string_demons
                self.findStrDemonInXml(string_demons)
                if self.config.method_to_string and method_demons:
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
                            traceback.print_exc()
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
            print('# Application info')
            print('\tPackageName:\t' + apk.getPackageName())
            doc = apk.getManifest().getFormatter().getPresentation(0).getDocument()
            self.text = TextDocumentUtil.getText(doc).encode("utf-8")
            self.root = ET.fromstring(self.text)

            shareUserId = self.root.get('{http://schemas.android.com/apk/res/android}sharedUserId')
            if not shareUserId or shareUserId.startswith('@'):
                shareUserId = None

            self.shareUserId = shareUserId

            self.packageName = apk.getPackageName()
        except Exception as e:
            traceback.print_exc()
            print('[-] Error ' + str(e))

    def outputPackageInfo(self):
        try:
            self.output('[TOC]\n\n')
            self.output('# {} Application info'.format(self.packageName))
            self.output('\tFile:\t' + self.inputPath)
            self.output('\tPackageName:\t' + self.packageName)
            root = self.root
            self.output('\tVersionName:\t' + root.attrib['{http://schemas.android.com/apk/res/android}versionName'])
            self.output('\tVersionCode:\t' + root.attrib['{http://schemas.android.com/apk/res/android}versionCode'])
            if self.shareUserId:
                self.output('\tsharedUserId:\t' + self.shareUserId)

            self.outputDelimiter()

            self.output('# {} AndroidManifest'.format(self.packageName))
            self.output('\n```xml')
            self.output(self.text)
            self.output('```')

            self.outputDelimiter()

            self.output('# Permission')

            self.showPermission(root)
            self.outputDelimiter()

            self.output('# Export Component')

            for cm in ['activity', 'service', 'provider', 'receiver']:
                self.showExportComponent(root, cm)
                
            self.outputDelimiter()

            self.output('# Result')

        except Exception as e:
            traceback.print_exc()
            print('[-] Error ' + str(e))

    def showPermission(self, manifest):
        # https://developer.android.com/reference/android/R.attr#protectionLevel
        protection_map = {0: 'normal',
                          1: 'dangerous',
                          2: 'signature',
                          3: 'signatureOrSystem',
                          10: 'privileged',
                          2|10: 'signature|privileged'
                          }
        for iter in manifest.findall('permission'):
            level = -1
            try:               
                level = int(str(iter.get(self.getAndroidAttrib('protectionLevel'))), 16)
            except Exception as e:
                traceback.print_exc()
                print('[-] Error ' + str(e))
            level_str = 'error(unknown)'
            if level in protection_map:
                level_str = protection_map[level]
            self.output('\t[*] declare permission {} {}[{}]'.format(iter.get(self.getAndroidAttrib('name')), level_str, level))

    def showExportComponent(self, manifest, component):
        assert isinstance(manifest, ET.Element)
        for iter in manifest.iter(component):
            if iter.get(self.getAndroidAttrib('exported')) == 'true' \
                or iter.find('intent-filter') is not None:
                self.output('\t[!] {} {} export '.format(component, iter.get(self.getAndroidAttrib('name'))))
                for perm_attrib in ['permission', 'readPermission', 'writePermission', 'grantUriPermissions']:

                        permission = iter.get(self.getAndroidAttrib(perm_attrib))
                        if permission:
                            self.output('\t\t[!] {} {} '.format(perm_attrib, permission))


    @staticmethod
    def getAndroidAttrib(name):
        return '{http://schemas.android.com/apk/res/android}' + name

    def outputDelimiter(self):
        self.output('\n' + '-' * 80 + '\n')

    def printDelimiter(self):
        print('-' * 80)

    def printMsg(self, msg):
        self.printDelimiter()
        print(msg)
        self.printDelimiter()

    def findStrDemonInXml(self, str_demons):
        lines = self.text.split('\n')
        for i in range(0, len(lines)):
            for demon in str_demons:
                if demon in lines[i]:
                    self.outputDelimiter()
                    # self.output('>' * 80)
                    self.output('[!]  \n[!] found {} string in xml  \n[!]  '.format(demon))
                    self.output('\n```xml')
                    if i > 0:
                        self.output(lines[i-1])
                    self.output(lines[i])
                    if i < len(lines) - 1:
                        self.output( lines[i+1])
                    self.output('```\n')
                    self.outputDelimiter()
                    # self.output('<' * 80)

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
                    self.outputDelimiter()
                    # self.output('>' * 80)
                    self.output('[!]  \n[!] found {} string  \n[!] '.format(dexStrValue))
                    self.findRef(DexPoolType.STRING, i, n, '\n[string] \'{}\'  '.format(dexStrValue))

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
                self.outputDelimiter()
                # self.output('>' * 80)
                self.output('[!]  \n[!] found {} method  \n[!]  '.format(methodSig))
                ref_str += '\n[method] \'{}\'  '.format(methodSig)
            # self.dex.getCrossReferences(DexPoolType.METHOD, decMethod)
            self.findRef(DexPoolType.METHOD, decMethod.getIndex(), n, ref_str)
        else:
            self.outputDelimiter()
            #self.output('<' * 80 + '\n')

    def findRef(self, poolType, index, n, ref_str):
        n = n - 1
        for addr in self.dex.getCrossReferences(poolType, index):
            if isinstance(addr, IDexAddress):
                # print(addr)
                addr = str(addr)
                r_method = addr.split('+')[0]
                current_ref_str = '{}  \n\t^  \n\tcall  \n\t^  \n[method] \'{}\' '.format(ref_str, addr)
                if r_method in ref_str:
                    self.output('[!] infinite loop \n {} \n[!] infinite loop'.format(current_ref_str))
                    return
                # if r_method in references:
                #     continue
                # references.add(r_method)
                self.output(current_ref_str)
                self.output('\n\n')
                javaMethod = self.getDecompiledMethod(self.dex, r_method)
                if javaMethod is None:
                    self.output('[-] Error: The method was not found or was not decompiled {}'.format(r_method))
                    continue
                text = self.decomp.getDecompiledMethodText(r_method)
                # print('/' + '*' * (n + 1))
                self.output('```java')
                for line in text.split('\n'):
                    self.output((' ' * (n + 1)) + ' ' + line)
                self.output('```')
                # print('*' * (n + 1) + '/')
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

    def find_intent(self):
        assert isinstance(self.dex, IDexUnit)
        get_object = self.dex.getMethod('LIntent')
        for addr in self.dex.getCrossReferences(DexPoolType.METHOD, get_object.getIndex()):
            if isinstance(addr, IDexAddress):
                r_method = str(addr).split('+')[0]
                # if r_method in references:
                #     continue
                # references.add(r_method)
                # current_ref_str = '{}\n\t\t^\n\t\tcall\n\t\t^\n[method] \'{}\''.format(ref_str, str(addr))
                # self.output(current_ref_str)
                # self.output('')
                java_method = self.getDecompiledMethod(self.dex, r_method)
                assert isinstance(java_method, IJavaMethod)
                if java_method is None:
                    self.output('[-] Error: The method was not found or was not decompiled')
                    return
                block = java_method.getBody()

                for i in range(block.size()):
                        self.view_element(block.get(i), 0)

                text = self.decomp.getDecompiledMethodText(r_method)
                # print('/' + '*' * (n + 1))
                self.output('```java')
                for line in text.split('\n'):
                    self.output(line)
                self.output('```')
                # print('*' * (n + 1) + '/')


    def view_element(self, statement, depth):
        print("    "*depth + repr(statement).strip() + " [" + repr(statement.getElementType()) + "]")
        for sub in statement.getSubElements():
            self.view_element(sub, depth+1)
