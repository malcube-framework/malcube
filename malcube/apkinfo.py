import functools
import hashlib
import os
import re

from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex


class Apkinfo:
    """Information about apk based on androguard analysis"""

    __slots__ = [
        "ret_type",
        "apk",
        "dalvikvmformat",
        "analysis",
        "apk_filename",
        "apk_filepath",
    ]

    def __init__(self, apk_filepath):
        """Information about apk based on androguard analysis"""
        self.ret_type = androconf.is_android(apk_filepath)

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(apk_filepath)

        if self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeDex(apk_filepath)

        self.apk_filename = os.path.basename(apk_filepath)
        self.apk_filepath = apk_filepath

    def __repr__(self):
        return f"<Apkinfo-APK:{self.apk_filename}>"

    @property
    def filename(self):
        """
        Return the filename of apk.
        :return: a string of apk filename
        """
        return os.path.basename(self.apk_filepath)

    @property
    def filesize(self):
        """
        Return the file size of apk file by bytes.
        :return: a number of size bytes
        """
        return os.path.getsize(self.apk_filepath)

    @property
    def md5(self):
        """
        Return the md5 checksum of the apk file.
        :return: a string of md5 checksum of the apk file
        """
        md5 = hashlib.md5()
        with open(self.apk_filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @property
    def permissions(self):
        """
        Return all permissions from given APK.
        :return: a list of all permissions
        """
        if self.ret_type == "APK":
            return self.apk.get_permissions()

        if self.ret_type == "DEX":
            return []

    @property
    def android_apis(self):
        """
        Return all Android native APIs from given APK.
        :return: a set of all Android native APIs MethodAnalysis
        """
        apis = set()

        for external_cls in self.analysis.get_external_classes():
            for meth_analysis in external_cls.get_methods():
                if meth_analysis.is_android_api():
                    apis.add(meth_analysis)

        return apis

    @property
    def custom_methods(self):
        """
        Return all custom methods from given APK.
        :return: a set of all custom methods MethodAnalysis
        """
        custom_methods = set()

        for meth_analysis in self.analysis.get_methods():
            if meth_analysis.is_external():
                continue
            custom_methods.add(meth_analysis)

        return custom_methods

    @property
    def all_methods(self):
        """
        Return all methods including Android native API and custom methods from given APK.
        :return: a set of all method MethodAnalysis
        """

        all_methods = set()

        for meth_analysis in self.analysis.get_methods():
            all_methods.add(meth_analysis)

        return all_methods

    @functools.lru_cache()
    def find_method(self, class_name=".*", method_name=".*", descriptor=".*"):
        """
        Find method from given class_name, method_name and the descriptor.
        default is find all method.
        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :param descriptor: the descriptor of the Android API
        :return: a generator of MethodClassAnalysis
        """

        regex_class_name = re.escape(class_name)
        regex_method_name = f"^{re.escape(method_name)}$"
        regex_descriptor = re.escape(descriptor)

        method_result = self.analysis.find_methods(
            classname=regex_class_name,
            methodname=regex_method_name,
            descriptor=regex_descriptor,
        )
        if list(method_result):
            (result,) = list(
                self.analysis.find_methods(
                    classname=regex_class_name,
                    methodname=regex_method_name,
                    descriptor=regex_descriptor,
                )
            )

            return result
        else:
            return None

    @functools.lru_cache()
    def xref_from(self, method_analysis):
        """
        Return the xref from method from given method analysis instance.
        :param method_analysis: the method analysis in androguard
        :return: a set of all xref from functions
        """
        xref_from_result = set()

        for _, call, _ in method_analysis.get_xref_from():
            # Call is the MethodAnalysis in the androguard
            # call.class_name, call.name, call.descriptor
            xref_from_result.add(call)

        return xref_from_result

    def get_strings(self):

        all_strings = set()

        for string_analysis in self.analysis.get_strings():
            all_strings.add(str(string_analysis.get_orig_value()))

        return all_strings
