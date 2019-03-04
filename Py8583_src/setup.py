from distutils.core import setup, Extension
setup(name="Py8583", version="1.0",
      ext_modules=[Extension("Py8583", ["Py8583.cpp"])])
